import frappe

from frappe_azure_blob_storage.blob_controllers.blob_store import BlobStore, change_file_privacy, upload_local_file
from frappe_azure_blob_storage.utils.cache import invalidate_from_file_url
from frappe_azure_blob_storage.utils.error import generate_error_log


def before_insert(doc, method):
    """
    Event handler for the 'after_insert' event of the File document.
    This function is used to upload a file to Azure Blob Storage when a new File document is created.
    """
    settings = frappe.get_single("Azure Storage Settings")
    if not settings.auto_upload_to_azure:
        return

    store = BlobStore()
    if not store.is_local_file(doc.file_url):
        return

    doc = upload_local_file(file_doc=doc)


def on_update(doc, method):
    """
    Event handler for the 'on_update' event of the File document.
    This function is used to update the File URL if the file is stored in Azure Blob Storage.
    """
    # Invalidate the download_file blob-key -> File.name cache whenever the
    # file_url changes (rename, privacy flip, etc.). Cheap Redis DEL, and it
    # keeps stale entries from surviving until TTL expiry.
    #
    # Gated on `not doc.flags.in_insert` because on insert there is no
    # prior state to invalidate — and `get_doc_before_save()` is None
    # anyway. Also bind the doc_before_save lookup to a local so we don't
    # call it twice.
    if not doc.flags.in_insert and doc.has_value_changed("file_url"):
        before = doc.get_doc_before_save()
        if before:
            invalidate_from_file_url(before.file_url)
        invalidate_from_file_url(doc.file_url)

    if (
        doc.flags.in_insert  # ignore if this is a new file being inserted
        or not doc.has_value_changed("is_private")
        or BlobStore.is_local_file(doc.file_url)
    ):
        return

    settings = frappe.get_single("Azure Storage Settings")
    if not settings.auto_upload_to_azure:
        return
    blob_store = BlobStore()
    if blob_store.is_ignored_dtype(doc.attached_to_doctype):
        return

    blob_name = blob_store.parse_url(doc.file_url)
    if not blob_name:
        generate_error_log(
            "File URL parsing failed",
            f"Failed to parse file URL: {doc.file_url}",
            exception=frappe.get_traceback(),
        )
        raise frappe.ValidationError(f"Cannot update file {doc.file_url}: Invalid file URL.")

    prev_url = doc.file_url
    # Belt-and-braces: explicitly drop the pre-flip cache entry before we
    # rewrite file_url via raw SQL. The block at the top of `on_update`
    # already invalidates when `has_value_changed("file_url")` is True,
    # but here only `is_private` may have changed — file_url is still the
    # pre-flip URL — so we invalidate here too. The following
    # `frappe.db.set_value` bypasses doc events, so this is our only
    # chance to prevent a stale docname from surviving until TTL.
    invalidate_from_file_url(prev_url)
    # Generate a placeholder URL for the file while it is being moved
    frappe.db.set_value("File", doc.name, "file_url", blob_store.get_file_link("in-transit"))

    frappe.enqueue(
        change_file_privacy,
        queue="long",
        job_id=f"moving_blob_{doc.name}",
        deduplicate=True,
        file_id=doc.name,
        to_private=doc.is_private,
        prev_url=prev_url,
        enqueue_after_commit=True,
    )


def after_rename(doc, method, old_name, new_name, merge):
    """
    Event handler for the 'after_rename' event of the File document.
    A rename changes `File.name`, which is the value our download_file cache
    stores against a blob key — invalidate so the next lookup repopulates
    with the new docname.
    """
    invalidate_from_file_url(doc.file_url)


def on_trash(doc, method):
    """
    Event handler for the 'on_trash' event of the File document.
    This function is used to delete a file from Azure Blob Storage when it is deleted in Frappe.
    """
    # Always drop the download_file lookup cache for this URL — even for
    # local files we may have populated it during a privacy transition.
    invalidate_from_file_url(doc.file_url)

    if BlobStore.is_local_file(doc.file_url):
        return

    blob_store = BlobStore()

    if blob_store.is_ignored_dtype(doc.attached_to_doctype):
        return

    blob_name = blob_store.parse_url(doc.file_url)
    if not blob_name:
        generate_error_log(
            "File URL parsing failed",
            f"Failed to parse file URL: {doc.file_url}",
            exception=frappe.get_traceback(),
        )
        raise frappe.ValidationError(f"Cannot delete file {doc.file_url}: Invalid file URL.")
    container_name = (
        blob_store.get_private_container_name() if doc.is_private else blob_store.get_public_container_name()
    )
    blob_store.delete_blob(container_name=container_name, blob_name=blob_name)
