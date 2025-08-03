import frappe
from frappe import _

from frappe_azure_blob_storage.blob_controllers.blob_store import BlobStore
from frappe_azure_blob_storage.utils.http import http_response


@frappe.whitelist()
def test_connection():
    """
    Test the connection to Azure Blob Storage using the credentials
    stored in 'Azure Storage Settings'.
    """
    try:
        settings = frappe.get_single("Azure Storage Settings")
        if not settings:
            return {"status": "error", "message": "Azure Storage Settings not found."}

        blob_store = BlobStore()
        blob_store.blob_service_client.get_service_properties()  # This will raise an error if connection fails

        return http_response("Connection to Azure Blob Storage is successful.")

    except Exception as e:
        return http_response(
            _("Failed to connect to Azure Blob Storage: {}").format(str(e)),
            success=False,
        )


@frappe.whitelist()
def migrate_files():
    """
    Migrate files from local storage to Azure Blob Storage.
    This function assumes that the files are stored in a specific directory
    and uploads them to the configured Azure Blob Storage container.
    """
    try:
        blob_store = BlobStore()
        files_list = frappe.get_all("File", fields=["file_name", "file_url"])
        for file in files_list:
            if file["file_url"]:
                blob_store.upload_existing_file(file["file_name"])

        return http_response("File migration to Azure Blob Storage completed successfully.")

    except Exception as e:
        return http_response(
            _("Failed to migrate files to Azure Blob Storage: {}").format(str(e)),
            success=False,
        )
