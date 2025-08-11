// Copyright (c) 2025, rtCamp and contributors
// For license information, please see license.txt

frappe.ui.form.on("Azure Storage Settings", {
	refresh: function (frm) {
		if (!frm.is_new()) {
			frm.add_custom_button(__("Migrate Files"), () => {
				frm.events.migrate_files(frm);
			});
		}
	},

	check_connection: function (_) {
		frappe.call({
			method: "frappe_azure_blob_storage.api.azure_blob.test_connection",
			callback: function (r) {
				if (r.success === true) {
					frappe.show_alert({
						message: __(r.message),
						indicator: "green",
					});
				} else {
					frappe.show_alert({
						message: __(
							"Invalid credentials! Please check your Azure Storage Settings."
						),
						indicator: "red",
					});
				}
			},
		});
	},
	migrate_files: function (_) {
		frappe.call({
			method: "frappe_azure_blob_storage.api.azure_blob.migrate_files",
			callback: function (r) {
				if (r.success === true) {
					frappe.show_alert({
						message: __("Migration started successfully!"),
						indicator: "green",
					});
				} else {
					frappe.show_alert({
						message: __("Error: " + r.message),
						indicator: "red",
					});
				}
			},
		});
	},
});
