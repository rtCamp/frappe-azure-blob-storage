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
            return http_response("Azure Storage Settings not found.")

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
        files_list = frappe.get_all("File", fields=["file_name", "file_url"])
        for index, file in enumerate(files_list):
            if blob_store.is_local_file(file["file_url"]):
                blob_store.upload_local_file(
                    file["file_name"],
                    remove_original=True,
                )
            # Update progress
            progress = int((index + 1) / len(files_list) * 100)
            frappe.publish_progress(
                progress,
                title=_("Azure File Migration"),
                description=_("Migrating files to Azure Blob Storage..."),
            )

        # Final progress update to signify completion
        frappe.publish_progress(
            100,
            title=_("Azure File Migration"),
            description=_("Migration completed successfully!"),
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


@frappe.whitelist()
def download_private_file(file_name: str):
    """
    A proxy method to securely download private files from Azure.
    It checks file permissions and then redirects to a temporary SAS URL.
    """
    try:
        # 1. Get the File document
        file_url = BlobStore.get_private_file_link(file_name)
        file_doc = frappe.get_doc("File", {"file_url": file_url})

        # 2. Check permissions
        if not file_doc.is_private:
            # If for some reason a public file URL points here, just redirect
            frappe.local.response["type"] = "redirect"
            frappe.local.response["location"] = file_doc.file_url
            return

        # This is Frappe's standard permission check for files
        if not frappe.has_permission("File", "read", file_doc):
            raise frappe.PermissionError

        # 3. Ensure the file is actually in Azure
        if BlobStore.is_local_file(file_doc.file_url):
            raise frappe.ValidationError(_("This file is not stored on Azure."))

        # 4. Generate the SAS URL
        blob_store = BlobStore()
        blob_name = file_name
        sas_url = blob_store.generate_sas_url(
            blob_name=blob_name,
            container_name=blob_store.get_private_container_name(),
        )

        # 5. Redirect the user to the temporary URL
        frappe.local.response["type"] = "redirect"
        frappe.local.response["location"] = sas_url

    except frappe.DoesNotExistError:
        frappe.throw(_("File not found."), frappe.NotFound)
    except Exception as e:
        frappe.log_error(title="Private File Download", message=frappe.get_traceback())
        frappe.throw(_("Could not retrieve file. Error: {0}").format(str(e)))
