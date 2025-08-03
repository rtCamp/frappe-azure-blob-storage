import frappe
from frappe import _

from frappe_azure_blob_storage.blob_controllers.blob_store import BlobStore
from frappe_azure_blob_storage.utils.error import generate_error_log
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
        frappe.enqueue(
            _run_migrate_job,
            queue="long",
            job_name="Migrate Files to Azure Blob Storage",
            timeout=600,
        )

        return http_response(_("File migration to Azure Blob Storage has been queued successfully."))

    except Exception as e:
        return http_response(
            _("Failed to migrate files to Azure Blob Storage: {}").format(str(e)),
            success=False,
        )


def _run_migrate_job():
    """
    Migrate files from local storage to Azure Blob Storage.
    This function assumes that the files are stored in a specific directory
    and uploads them to the configured Azure Blob Storage container.
    """
    try:
        blob_store = BlobStore()
        files_list = frappe.get_all("File", fields=["file_name", "file_url", "is_private"])
        for file in files_list:
            if blob_store.is_local_file(file["file_url"]):
                blob_store.upload_local_file(
                    file["file_name"],
                    remove_original=True,
                    private=file.get("is_private", True),
                )

        frappe.msgprint(
            _("File migration to Azure Blob Storage completed successfully."),
            realtime=True,
        )

    except Exception as e:
        generate_error_log(
            "Azure Blob Storage Migration Error",
            frappe.get_traceback(),
            exception=e,
        )
        return frappe.msgprint(
            _("Failed to migrate files to Azure Blob Storage"),
            realtime=True,
        )
