# Copyright (c) 2025, rtCamp and contributors
# For license information, please see license.txt

import frappe
from frappe.model.document import Document


class AzureStorageSettings(Document):
    # begin: auto-generated types
    # This code is auto-generated. Do not modify anything in this block.

    from typing import TYPE_CHECKING

    if TYPE_CHECKING:
        from frappe.types import DF

        from frappe_azure_blob_storage.frappe_azure_blob_storage.doctype.azure_storage_ignored_doctyoe.azure_storage_ignored_doctyoe import (
            AzureStorageIgnoredDocTyoe,
        )

        access_key: DF.Password | None
        authentication_method: DF.Literal["Connection String", "Access Key"]
        auto_upload_to_azure: DF.Check
        connection_string: DF.Password | None
        default_container_name: DF.Data
        endpoint_suffix: DF.Data
        ignored_doctypes: DF.TableMultiSelect[AzureStorageIgnoredDocTyoe]
        remove_original_files: DF.Check
        sas_token_validity: DF.Int
        storage_account_name: DF.Data
    # end: auto-generated types

    def validate(self):
        """
        Validate the Azure Storage Settings document.
        This method checks if the required fields are set and valid.
        """
        if self.sas_token_validity < 60:
            frappe.throw(frappe._("SAS Token Validity must be at least 60 seconds."))
