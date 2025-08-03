from urllib.parse import parse_qs, urljoin

import frappe
from frappe import clear_messages
from frappe.utils import get_request_session

from frappe_azure_blob_storage.utils.error import generate_error_log


def safe_urljoin(base: str, path: str) -> str:
	"""
	Safely join base and path, ensuring path is appended to base
	even if it starts with a slash.

	Args:
	    base (str): The base URL (e.g., 'https://example.com/api')
	    path (str): The path to append (e.g., 'v1/resource' or '/v1/resource')

	Returns:
	    str: A well-formed URL with the path appended to the base
	"""
	base = base.rstrip("/") + "/"  # Ensure base ends with a single /
	path = path.lstrip("/")  # Remove any leading / from path
	return urljoin(base, path)


def http_response(
	message: str | None = None,
	*,
	body: dict | None = None,
	status_code: int = 200,
	success: bool = True,
	data: dict | None = None,
	is_empty: bool = False,
) -> None:
	"""
	Send an HTTP response with the given status code and data using frappe.response
	If `is_empty` is True, the response will be empty
	If `body` is provided, it will be used as the raw response
	Otherwise, return a formatted JSON response
	"""
	# Clear existing messages
	clear_messages()
	if frappe.flags.error_message:
		frappe.flags.error_message = None

	# Set the status code
	frappe.response["http_status_code"] = status_code

	# Handle empty response
	if is_empty:
		frappe.response.update({})
		return

	# Handle raw body response
	if body:
		frappe.response.update(body)
		return

	# Handle formatted JSON response
	response_data = {
		"success": success and status_code >= 200 and status_code < 400,
		"message": message,
		"data": data or {},
	}

	frappe.response.update(response_data)


def log_request(method, url, body, response, id=None) -> None:
	message = f"Request:\n----------------------------\n{method} {url}\nBody: {frappe.as_json(body)}\n\n"
	try:
		message += (
			f"Response (Status {response.status_code}):\n"
			"----------------------------\n"
			f"{frappe.as_json(response.json())}"
		)
	except Exception as e:
		message += f"Response had exception: {e}"

	title = id or "External HTTP Request"
	generate_error_log(title, message=message)


def http_request(
	method,
	url,
	auth=None,
	headers=None,
	data=None,
	json=None,
	params=None,
	log_always=frappe.conf.developer_mode,
	id=None,
):
	auth = auth or ""
	data = data or {}
	headers = headers or {}
	response = None

	try:
		s = get_request_session()
		response = s.request(method, url, data=data, auth=auth, headers=headers, json=json, params=params)
		response.raise_for_status()

		if log_always:
			log_request(method, url, json or data, response, id)
		# Check whether the response has a content-type, before trying to check what it is
		if content_type := response.headers.get("content-type"):
			if content_type == "text/plain; charset=utf-8":
				return parse_qs(response.text)
			elif content_type.startswith("application/") and content_type.split(";")[0].endswith("json"):
				return response.json()
			elif response.text:
				return response.text
		return
	except Exception as exc:
		log_request(method, url, json or data, response, id)
		raise exc
