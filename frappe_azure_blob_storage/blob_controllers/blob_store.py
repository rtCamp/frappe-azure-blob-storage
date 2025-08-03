import frappe
from azure.core.exceptions import AzureError, ResourceExistsError
from azure.storage.blob import BlobServiceClient
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

	def upload_existing_file(self, file_name: str) -> None:
		"""
		Uploads an existing file to Azure Blob Storage.

		:param file_name: The name of the file to upload.
		:param file_url: The URL of the file to upload.
		"""
		try:
			file_url = frappe.db.get_value("File", {"file_name": file_name}, "file_url")
			if not file_url:
				generate_error_log(
					_("File Not Found"),
					_("The specified file does not exist in the database."),
					throw_exc=True,
				)

			# Ensure container exists (no-op if already exists)
			try:
				self.blob_service_client.create_container(self.settings.default_container_name)
			except ResourceExistsError:
				pass

			blob_client = self.blob_service_client.get_blob_client(
				container=self.settings.default_container_name, blob=file_name
			)
			with open(get_file_path(file_name), "rb") as data:
				blob_client.upload_blob(data, overwrite=True)
			frappe.db.set_value("File", file_name, "file_url", blob_client.url)

		except AzureError as e:
			generate_error_log(
				_("Azure Blob Upload Error"),
				_("Failed to upload file to Azure Blob Storage."),
				exception=e,
				throw_exc=True,
			)
