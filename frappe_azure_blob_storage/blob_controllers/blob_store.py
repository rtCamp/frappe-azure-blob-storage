import os
from datetime import timedelta
from urllib.parse import quote

import frappe
import magic
from azure.core.exceptions import AzureError, ResourceExistsError
from azure.storage.blob import (
    BlobSasPermissions,
    BlobServiceClient,
    ContentSettings,
    generate_blob_sas,
)
from frappe import _
from frappe.utils.file_manager import get_file_path

from frappe_azure_blob_storage.utils.error import generate_error_log


class BlobStore:
    """
    A class to manage Azure Blob Storage operations.

    This class provides methods to upload and download blobs from Azure Blob Storage.
    It requires an instance of `BlobServiceClient` to interact with the storage account.
    """

    def __init__(self, blob_service_client: BlobServiceClient | None = None):
        """
        Initializes the BlobServiceClient by fetching credentials from
        the 'Azure Storage Settings' Doctype.
        """
        self.settings = frappe.get_single("Azure Storage Settings")
        self.blob_service_client = blob_service_client or self._get_blob_service_client()

        # Ensure appropriate containers
        self._ensure_container_exists(self.get_public_container_name(), public=True)
        self._ensure_container_exists(self.get_private_container_name(), public=False)

    def get_public_container_name(self) -> str:
        """
        Returns the name of the public container.
        """
        return f"{self.settings.default_container_name}-public"

    def get_private_container_name(self) -> str:
        """
        Returns the name of the private container.
        """
        return f"{self.settings.default_container_name}-private"

    def _ensure_container_exists(self, container_name: str, public: bool = False):
        """
        Create a container if it doesn't exist.
        Set public access if requested.
        """
        try:
            container_client = self.blob_service_client.get_container_client(container_name)

            try:
                container_client.create_container()
            except ResourceExistsError:
                # This is expected if the container is already there.
                pass

            if public:
                container_client.set_container_access_policy(signed_identifiers={}, public_access="blob")

        except Exception as e:
            generate_error_log(
                _("Azure Container Error"),
                _("Failed to initialize container '{0}'.").format(container_name),
                exception=e,
                throw_exc=True,
            )

    def generate_sas_url(
        self,
        blob_name: str,
        container_name: str | None = None,
    ) -> str:
        """
        Generates a temporary SAS URL to allow read access to a private blob.

        :param container_name: The name of the private container.
        :param blob_name: The name of the blob.
        :return: A full URL with a SAS token for temporary access.
        """
        if container_name is None:
            container_name = self.get_private_container_name()

        blob_client = self.blob_service_client.get_blob_client(container=container_name, blob=blob_name)

        # Generate a SAS token that's valid for 15 minutes
        sas_token = generate_blob_sas(
            account_name=blob_client.account_name,
            container_name=container_name,
            blob_name=blob_name,
            account_key=self.blob_service_client.credential.account_key,
            permission=BlobSasPermissions(read=True),
            expiry=frappe.utils.now_datetime() + timedelta(minutes=15),
        )

        return f"{blob_client.url}?{sas_token}"

    def _get_blob_service_client(self) -> BlobServiceClient:
        """
        Creates and returns a BlobServiceClient based on the authentication
        method specified in the settings.
        """
        auth_method = self.settings.authentication_method

        try:
            if auth_method == "Connection String":
                connection_string = self.settings.get_password("connection_string")
                if not connection_string:
                    generate_error_log(
                        _("Azure Storage Settings Error"),
                        _("Connection String is not set in Azure Storage Settings."),
                        throw_exc=True,
                    )
                return BlobServiceClient.from_connection_string(connection_string)

            elif auth_method == "Account Access Key":
                account_name = self.settings.storage_account_name
                access_key = self.settings.get_password("access_key")
                if not account_name or not access_key:
                    generate_error_log(
                        _("Azure Storage Settings Error"),
                        _("Storage Account Name or Access Key is not set in Azure Storage Settings."),
                        throw_exc=True,
                    )

                account_url = f"https://{account_name}.blob.core.windows.net"
                return BlobServiceClient(account_url=account_url, credential=access_key)

            else:
                generate_error_log(
                    _("Azure Storage Settings Error"),
                    _("Invalid Authentication Method specified in Azure Storage Settings."),
                    throw_exc=True,
                )

        except AzureError as e:
            generate_error_log(
                _("Azure Authentication Error"),
                _("Failed to connect to Azure Storage. Please check your credentials."),
                exception=e,
                throw_exc=True,
            )
        except Exception as e:
            generate_error_log(
                _("Azure Authentication Error"),
                _("An unexpected error occurred during BlobStore initialization"),
                exception=e,
                throw_exc=True,
            )

    def upload_local_file(self, file_name: str, private: bool = True, remove_original: bool = False) -> None:
        """
        Uploads an existing file to Azure Blob Storage.
        """
        try:
            file_url = frappe.db.get_value("File", {"file_name": file_name}, "file_url")
            if not file_url:
                generate_error_log(
                    _("File Not Found"),
                    _("The specified file does not exist in the database."),
                    throw_exc=True,
                )

            blob_client = self.blob_service_client.get_blob_client(
                container=(
                    self.get_public_container_name() if not private else self.get_private_container_name()
                ),
                blob=file_name,
            )
            full_file_path = get_file_path(file_name)
            with open(full_file_path, "rb") as data:
                blob_client.upload_blob(
                    data,
                    overwrite=True,
                    content_settings=ContentSettings(
                        content_type=magic.from_file(full_file_path, mime=True),
                        content_disposition=f"inline; filename={file_name}",
                    ),
                )
            if remove_original:
                os.remove(full_file_path)
            frappe.db.set_value(
                "File",
                {"file_name": file_name},
                "file_url",
                (
                    blob_client.url
                    if not private
                    else f"/api/method/frappe_azure_blob_storage.api.blob_apis.download_private_file?file_name={quote(file_name)}"
                ),
            )
            frappe.db.commit()

        except AzureError as e:
            generate_error_log(
                _("Azure Blob Upload Error"),
                _("Failed to upload file to Azure Blob Storage."),
                exception=e,
                throw_exc=True,
            )

    @classmethod
    def is_local_file(cls, file_url: str) -> bool:
        return file_url and (not file_url.startswith("http") and not file_url.startswith("/api/method"))
