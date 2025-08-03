import frappe


def generate_error_log(
    title: str,
    message: str = "",
    *,
    exception: Exception | None = None,
    msgprint: bool = False,
    realtime: bool = False,
    throw_exc: bool = False,
):
    """
    Generate an error log with the given title and message
    """
    exc = str(exception)
    if not exc:
        exc = frappe.get_traceback()
    frappe.log_error(
        title="Azure: " + title,
        message=f"{message}\nException:\n{exc}" if exception else message,
    )

    if msgprint:
        frappe.msgprint(
            title=title,
            msg=message,
            indicator="red",
            realtime=realtime,
        )

    if throw_exc:
        raise frappe.throw(message)
