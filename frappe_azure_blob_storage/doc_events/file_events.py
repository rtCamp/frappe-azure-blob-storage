import frappe

from frappe_azure_blob_storage.blob_controllers.blob_store import BlobStore
from frappe_azure_blob_storage.utils.error import generate_error_log


def after_insert(doc, method):
    """
    Event handler for the 'after_insert' event of the File document.
    This function is used to upload a file to Azure Blob Storage when a new File document is created.
    """
    store = BlobStore()
    if not store.is_local_file(doc.file_url):
        return
    store.upload_local_file(doc.name)


def on_update(doc, method):
    """
    Event handler for the 'on_update' event of the File document.
    This function is used to update the File URL if the file is stored in Azure Blob Storage.
    """
    if not doc.has_value_changed("is_private") or BlobStore.is_local_file(doc.file_url):
        return

    blob_store = BlobStore()
    blob_details = blob_store.parse_url(doc.file_url)
    if not blob_details:
        generate_error_log(
            "File URL parsing failed",
            f"Failed to parse file URL: {doc.file_url}",
            exception=frappe.get_traceback(),
        )
        raise frappe.ValidationError(f"Cannot update file {doc.file_url}: Invalid file URL.")
    blob_store.move_blob(
        source_blob_key=blob_details.blob_name,
        destination_blob_key=blob_details.blob_name,
        to_private=doc.is_private,
    )


def on_trash(doc, method):
    """
    Event handler for the 'on_trash' event of the File document.
    This function is used to delete a file from Azure Blob Storage when it is deleted in Frappe.
    """
    if BlobStore.is_local_file(doc.file_url):
        return

    blob_store = BlobStore()
    blob_details = blob_store.parse_url(doc.file_url)
    if not blob_details:
        generate_error_log(
            "File URL parsing failed",
            f"Failed to parse file URL: {doc.file_url}",
            exception=frappe.get_traceback(),
        )
        raise frappe.ValidationError(f"Cannot delete file {doc.file_url}: Invalid file URL.")
    blob_store.delete_blob(container_name=blob_details.container_name, blob_name=blob_details.blob_name)
