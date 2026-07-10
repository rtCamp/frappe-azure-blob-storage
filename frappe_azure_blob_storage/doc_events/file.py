import frappe

from frappe_azure_blob_storage.blob_controllers.blob_store import BlobStore, change_file_privacy, upload_local_file
from frappe_azure_blob_storage.utils.cache import invalidate_from_file_url
from frappe_azure_blob_storage.utils.error import generate_error_log


def before_insert(doc, method):
    settings = frappe.get_single("Azure Storage Settings")
    if not settings.auto_upload_to_azure:
        return

    store = BlobStore()
    if not store.is_local_file(doc.file_url):
        return

    doc = upload_local_file(file_doc=doc)


def on_update(doc, method):
    if not doc.flags.in_insert and doc.has_value_changed("file_url"):
        before = doc.get_doc_before_save()
        if before:
            invalidate_from_file_url(before.file_url)
        invalidate_from_file_url(doc.file_url)

    if doc.flags.in_insert or not doc.has_value_changed("is_private") or BlobStore.is_local_file(doc.file_url):
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
    # set_value below bypasses doc events, so invalidate manually.
    invalidate_from_file_url(prev_url)
    frappe.db.set_value("File", doc.name, "file_url", blob_store.get_file_link("in-transit"))
    # Second invalidation shrinks (does not close) the race window where a
    # concurrent download_file repopulates the stale mapping between the
    # first invalidate and the set_value. The enqueued change_file_privacy
    # job re-saves the doc post-commit and fires on_update again for the
    # final cleanup.
    invalidate_from_file_url(prev_url)

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
    # Rename changes File.name (the cache VALUE) but not file_url (the
    # cache KEY derivation), so drop the entry keyed on the current URL.
    invalidate_from_file_url(doc.file_url)


def on_trash(doc, method):
    # Drop the lookup cache even for local files — an entry may have been
    # populated during a prior privacy transition.
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
