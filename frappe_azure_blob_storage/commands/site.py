import frappe
from frappe.commands import get_site, pass_context


def init_site_decorate(function):
    """
    This function is a decorator that initializes and connects to a Frappe site,
    executes the decorated function, and then commits any changes and destroys the site instance.

    Parameters:
    function (function): The function to be decorated.

    Returns:
    wrap_function (function): The decorated function.
    """

    @pass_context
    def wrap_function(context, *args, **kwargs):
        try:
            site = get_site(context)

            frappe.init(site=site)
            frappe.connect()

        except Exception:
            print("Please specify --site sitename")

        function(*args, **kwargs)

        # nosemgrep
        frappe.db.commit()

        frappe.destroy()

    return wrap_function
