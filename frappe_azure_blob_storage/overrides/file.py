import frappe
from frappe.core.doctype.file.file import File


class FileOverride(File):
    def get_content(self, encodings=None) -> bytes | str:
        if hasattr(self, "custom_uploaded_to_azure") and not self.custom_uploaded_to_azure:
            return super().get_content(encodings=encodings)
        if self.is_folder:
            frappe.throw(frappe._("Cannot get file contents of a Folder"))

        from frappe_azure_blob_storage.blob_controllers.blob_store import BlobStore

        blob_store = BlobStore()
        blob_name = blob_store.parse_url(self.file_url)

        if not blob_name:
            frappe.throw(frappe._("Could not extract file name from URL: {0}").format(self.file_url))

        container_name = (
            blob_store.get_private_container_name() if self.is_private else blob_store.get_public_container_name()
        )

        blob_client = blob_store.blob_service_client.get_blob_client(container=container_name, blob=blob_name)
        return blob_client.download_blob().readall()
