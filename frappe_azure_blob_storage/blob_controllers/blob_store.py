import os
import re
from datetime import timedelta
from urllib.parse import parse_qs, quote, urlparse

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
        self._ensure_container_exists(self.get_public_container_name(), is_public=True)
        self._ensure_container_exists(self.get_private_container_name(), is_public=False)

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

    def _ensure_container_exists(self, container_name: str, is_public: bool = False):
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

            if is_public:
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
        ignore_cache: bool = False,
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
        cache_key = f"azure_blob_sas_url::{container_name}::{blob_name}"
        cached_url = frappe.cache().get(cache_key)
        if cached_url and not ignore_cache:
            return cached_url

        # Generate a SAS token that's valid for 15 minutes
        sas_token = generate_blob_sas(
            account_name=blob_client.account_name,
            container_name=container_name,
            blob_name=blob_name,
            account_key=self.blob_service_client.credential.account_key,
            permission=BlobSasPermissions(read=True),
            expiry=frappe.utils.now_datetime() + timedelta(seconds=self.settings.sas_token_validity),
        )

        full_url = f"{blob_client.url}?{sas_token}"
        # Cache the URL expire just 30 seconds before the actual expiry
        frappe.cache().set_value(cache_key, full_url, expires_in_sec=self.settings.sas_token_validity - 30)

        return full_url

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

                account_url = f"https://{account_name}.{self.settings.endpoint_suffix}"
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

    def strip_special_chars(self, file_name):
        """
        Strips file charachters which doesnt match the regex.
        """
        regex = re.compile("[^0-9a-zA-Z._-]")
        file_name = regex.sub("", file_name)
        return file_name

    def blob_key_generator(self, file_name, parent_doctype=None, parent_name=None, is_private=True):
        """
        Generate keys for s3 objects uploaded with file name attached.
        """
        # Check for custom key generator hook
        hook_cmd = frappe.get_hooks().get("s3_key_generator")
        if hook_cmd:
            try:
                custom_key = frappe.get_attr(hook_cmd[0])(
                    file_name=file_name,
                    parent_doctype=parent_doctype,
                    parent_name=parent_name,
                )
                if custom_key:
                    return custom_key.strip("/")
            except Exception as e:
                generate_error_log(
                    _("Custom Key Generator Error"),
                    _("An error occurred while executing the custom key generator."),
                    exception=e,
                )

        file_name = self.strip_special_chars(frappe.scrub(file_name))
        unique_key = frappe.generate_hash(length=8)
        today = frappe.utils.now_datetime()
        year, month, day = (
            today.strftime("%Y"),
            today.strftime("%m"),
            today.strftime("%d"),
        )

        path_parts = [
            year,
            month,
            day,
            parent_doctype,
            parent_name,
            unique_key,
            file_name,
        ]

        final_key = "/".join(part for part in path_parts if part)
        return final_key

    def upload_local_file(self, file_id: str, remove_original: bool | None = None) -> None:
        """
        Uploads an existing file to Azure Blob Storage.
        """
        try:
            file_doc = frappe.get_doc("File", file_id)
            file_name = file_doc.file_name
            parent_doctype = file_doc.attached_to_doctype or "File"
            parent_name = file_doc.attached_to_name
            is_private = file_doc.is_private
            file_url = file_doc.file_url

            if not file_url:
                generate_error_log(
                    _("File Not Found"),
                    _("File {}:{} does not exist in the system.").format(file_id, file_url),
                    throw_exc=True,
                )

            file_blob_key = self.blob_key_generator(file_name, parent_doctype, parent_name, is_private)
            full_file_path = get_file_path(file_id)

            blob_url = self.upload_blob(
                file_key=file_blob_key,
                file_path=full_file_path,
                is_private=is_private,
            )
            if remove_original or (remove_original is None and self.settings.remove_original_files == 1):
                os.remove(full_file_path)

            frappe.db.set_value(
                "File",
                file_id,
                "file_url",
                blob_url,
            )
            frappe.db.commit()

        except AzureError as e:
            generate_error_log(
                _("Azure Blob Upload Error"),
                _("Failed to upload file to Azure Blob Storage."),
                exception=e,
                throw_exc=True,
            )

    def upload_blob(self, file_key: str, file_path: str, is_private: bool = True) -> str:
        """
        Uploads a file to Azure Blob Storage and returns the blob URL.
        """
        try:
            blob_client = self.blob_service_client.get_blob_client(
                container=(
                    self.get_public_container_name() if not is_private else self.get_private_container_name()
                ),
                blob=file_key,
            )
            full_file_path = file_path
            with open(full_file_path, "rb") as data:
                blob_client.upload_blob(
                    data,
                    overwrite=True,
                    content_settings=ContentSettings(
                        content_type=magic.from_file(full_file_path, mime=True),
                        content_disposition=f"inline; filename={quote(os.path.basename(full_file_path))}",
                    ),
                )
            return blob_client.url if not is_private else self.get_private_file_link(file_key)
        except AzureError as e:
            generate_error_log(
                _("Azure Blob Upload Error"),
                _("Failed to upload file to Azure Blob Storage."),
                exception=e,
                throw_exc=True,
            )

    def move_blob(
        self,
        source_blob_key: str,
        destination_blob_key: str,
        to_private: bool = True,
    ) -> None:
        """
        Moves a blob from one location to another within Azure Blob Storage.
        """
        try:
            private_container = self.get_private_container_name()
            public_container = self.get_public_container_name()

            if to_private:
                src_container, dest_container = public_container, private_container
            else:
                src_container, dest_container = private_container, public_container

            source_client = self.blob_service_client.get_blob_client(
                container=src_container, blob=source_blob_key
            )

            if not source_client.exists():
                generate_error_log(
                    "Blob Move Error",
                    f"Source blob {source_blob_key} not found in container {src_container} during move.",
                )
                frappe.throw(
                    _("Source blob {0} not found in container {1}.").format(source_blob_key, src_container),
                    frappe.DoesNotExistError,
                )
                return

            destination_client = self.blob_service_client.get_blob_client(
                container=dest_container, blob=destination_blob_key
            )

            destination_client.start_copy_from_url(source_client.url)

            # TODO: Poll for copy completion. For large files, this might need to be a background job.
            # copy_props = dest_client.get_blob_properties().copy
            # while copy_props.status == 'pending':
            #     time.sleep(1)
            #     copy_props = dest_client.get_blob_properties().copy
            #
            # if copy_props.status != 'success':
            #     raise Exception(f"Server-side copy failed with status: {copy_props.status}")

            # Delete the original blob
            # source_client.delete_blob()

            # Remove the cached SAS URL for the source blob
            frappe.cache().delete_value(f"azure_blob_sas_url::{src_container}::{source_blob_key}")
            return (
                destination_client.url if not to_private else self.get_private_file_link(destination_blob_key)
            )
        except AzureError as e:
            generate_error_log(
                _("Azure Blob Move Error"),
                _("Failed to move blob in Azure Blob Storage."),
                exception=e,
                throw_exc=True,
            )

    def delete_blob(self, container_name: str, blob_name: str):
        """
        Deletes a specific blob from a given container in Azure.

        :param container_name: The name of the container holding the blob.
        :param blob_name: The name of the blob to delete.
        """
        try:
            blob_client = self.blob_service_client.get_blob_client(container=container_name, blob=blob_name)
            # delete_blob() will not raise an error if the blob doesn't exist.
            blob_client.delete_blob()
        except Exception as e:
            # Log the error but don't prevent the Frappe document from being deleted.
            generate_error_log(
                "Azure Blob Deletion Error",
                f"Failed to delete blob '{blob_name}' from container '{container_name}'.",
                exception=e,
            )
            raise e

    @classmethod
    def get_private_file_link(cls, file_key: str) -> str:
        """
        Returns a temporary link to a private file stored in Azure Blob Storage.
        """
        # NOTE: It is better to provide the entire URL to the API method since Frappe internally
        # checks if the URL starts with `http` and handles operations accordingly.
        return f"{frappe.utils.get_url()}/api/method/frappe_azure_blob_storage.api.blob_apis.download_private_file?file_name={quote(file_key)}"

    @classmethod
    def is_local_file(cls, file_url: str) -> bool:
        return file_url and (not file_url.startswith("http") and not file_url.startswith("/api/method"))

    def parse_url(self, file_url: str) -> frappe._dict | None:
        """
        Parses a Frappe/Azure file URL to extract its components.

        Args:
            file_url: The URL of the file, which can be a private proxy URL
                    or a direct public Azure Blob Storage URL.

        Returns:
            A dict containing (container_name, blob_name, is_private).
            Returns None if the URL format is not recognized.
        """
        if not file_url:
            return None

        parsed_url = urlparse(file_url)

        # --- Handle Private Proxy URLs ---
        # e.g., /api/method/...?file_name=container/path/to/blob.pdf
        if "/api/method/" in parsed_url.path:
            query_params = parse_qs(parsed_url.query)
            blob_name = query_params.get("file_name", [None])[0]

            if blob_name:
                return frappe._dict(
                    container_name=self.get_private_container_name(),
                    blob_name=blob_name,
                    is_private=True,
                )

        # --- Handle Public Direct Azure URLs ---
        # e.g., https://account.blob.core.windows.net/container/path/to/blob.pdf
        elif self.settings.endpoint_suffix in parsed_url.netloc:
            # Path will be like /container_name/path/to/blob.pdf
            path_parts = parsed_url.path.strip("/").split("/")
            if path_parts:
                container_name = path_parts[0]
                # The rest of the path is the blob name
                blob_name = "/".join(path_parts[1:])
                return frappe._dict(
                    container_name=container_name,
                    blob_name=blob_name,
                    is_private=False,
                )

        # If neither format matches
        return None
