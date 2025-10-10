import frappe
from frappe import _

from frappe_azure_blob_storage.blob_controllers.blob_store import BlobStore, upload_local_file
from frappe_azure_blob_storage.utils.error import generate_error_log
from frappe_azure_blob_storage.utils.http import http_response


@frappe.whitelist(methods=["GET"])
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

        return http_response(_("Connection to Azure Blob Storage is successful."))

    except Exception as e:
        return http_response(
            _("Failed to connect to Azure Blob Storage: {}").format(str(e)),
            success=False,
        )


@frappe.whitelist(methods=["GET"])
def migrate_files():
    """
    Migrate files from local storage to Azure Blob Storage.
    This function assumes that the files are stored in a specific directory
    and uploads them to the configured Azure Blob Storage container.
    """
    try:
        page_idx = 0
        page_size = 100

        while True:
            files_list = frappe.get_all(
                "File",
                fields=["name", "file_url", "file_name"],
                filters=BlobStore.AZURE_FILE_FILTERS,
                limit_start=(page_idx * page_size),
                limit_page_length=page_size,
                order_by="creation asc",
            )
            if not files_list:
                # If no files are found in the first place, we can return
                if page_idx == 0:
                    return http_response(success=False, message=_("No new local files to migrate."))

                break

            frappe.enqueue(
                _run_migrate_job,
                queue="long",
                job_id=f"migrate_files_to_azure-part_{page_idx}",
                deduplicate=True,
                is_web_request=True,
                files_list=files_list,
            )
            page_idx += 1

        return http_response(_("File migration to Azure Blob Storage has been queued successfully."))

    except Exception as e:
        return http_response(
            _("Failed to migrate files to Azure Blob Storage: {}").format(str(e)),
            success=False,
        )


def _run_migrate_job(files_list: list | None = None, is_web_request: bool = True):
    """
    Migrate files from local storage to Azure Blob Storage.
    This function assumes that the files are stored in a specific directory
    and uploads them to the configured Azure Blob Storage container.
    """

    try:
        if files_list is None:
            files_list = frappe.get_all(
                "File",
                fields=["name", "file_url", "file_name"],
                filters=BlobStore.AZURE_FILE_FILTERS,
            )
        total_files = len(files_list)
        if not total_files:
            if not is_web_request:
                print("No new local files to migrate.")
            return

        for index, file in enumerate(files_list):
            file_id = file["name"]
            file_name = file["file_name"]
            try:
                upload_local_file(file_id=file_id)
            except FileNotFoundError:
                generate_error_log(
                    "File Migration Error",
                    f"File not found on local disk: {file_id}:{file_name}. Skipping.",
                )
                if is_web_request:
                    frappe.publish_progress(
                        100,
                        title=_("Azure File Migration"),
                        description=_("File not found: {0}. Skipping.").format(file_name),
                    )
                else:
                    print(
                        f"File not found on local disk: {file_id}:{file_name}. Skipping.",
                    )
                continue
            current_file_number = index + 1
            # Update progress
            progress = current_file_number / total_files * 100
            description = _("Migrating {0}/{1}: {2}").format(current_file_number, total_files, file_name)
            if is_web_request:
                frappe.publish_progress(
                    progress,
                    title=_("Azure File Migration"),
                    description=description,
                )
            else:
                print(description)
        # Final progress update to signify completion
        if is_web_request:
            frappe.publish_progress(
                100,
                title=_("Azure File Migration"),
                description=_("Migration completed successfully!"),
            )
            frappe.msgprint(
                _("File migration to Azure Blob Storage completed successfully."),
                realtime=True,
            )
        else:
            print("Migration completed successfully!")

    except Exception as e:
        generate_error_log(
            "Azure Blob Storage Migration Error",
            frappe.get_traceback(),
            exception=e,
        )
        if is_web_request:
            frappe.msgprint(
                _("Failed to migrate files to Azure Blob Storage"),
                realtime=True,
            )
        else:
            print(f"\nERROR: Migration failed. Check Error Log for details.\n{frappe.get_traceback()}")


@frappe.whitelist(methods=["GET"])
def download_private_file(file_name: str):
    """
    A proxy method to securely download private files from Azure.
    It checks file permissions and then redirects to a temporary SAS URL.
    """
    try:
        # --- Strip the ?fid=... query parameter ---
        # This ensures we get the clean file path from the URL.
        if "?fid=" in file_name:
            file_name = file_name.split("?fid=")[0]

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
        # The blob_name is the cleaned file_name from the start of the function
        sas_url = blob_store.generate_sas_url(
            blob_name=file_name,
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
