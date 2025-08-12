# Copyright (c) 2025, rtCamp and contributors
# For license information, please see license.txt

import frappe
from frappe.model.document import Document


class AzureStorageSettings(Document):
    def validate(self):
        """
        Validate the Azure Storage Settings document.
        This method checks if the required fields are set and valid.
        """
        if self.sas_token_validity < 60:
            frappe.throw(frappe._("SAS Token Validity must be at least 60 seconds."))
