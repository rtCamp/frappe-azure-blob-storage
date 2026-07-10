from urllib.parse import parse_qs, urlparse

import frappe

FILE_NAME_CACHE_KEY_PREFIX = "azure_dl_file_name"
FILE_NAME_CACHE_TTL_SECONDS = 60 * 60


def _build_cache_key(blob_key: str) -> str:
    return f"{FILE_NAME_CACHE_KEY_PREFIX}::{blob_key}"


def get_cached_file_name(blob_key: str) -> str | None:
    if not blob_key:
        return None
    return frappe.cache().get_value(_build_cache_key(blob_key))


def set_cached_file_name(blob_key: str, file_name: str) -> None:
    if not blob_key or not file_name:
        return
    frappe.cache().set_value(
        _build_cache_key(blob_key),
        file_name,
        expires_in_sec=FILE_NAME_CACHE_TTL_SECONDS,
    )


def invalidate_cached_file_name(blob_key: str) -> None:
    if not blob_key:
        return
    frappe.cache().delete_value(_build_cache_key(blob_key))


def invalidate_from_file_url(file_url: str) -> None:
    # Parse inline rather than via BlobStore — this runs from doc-event
    # hooks on every File save and BlobStore.__init__ reads settings from DB.
    blob_key = parse_blob_key_from_url(file_url)
    if blob_key:
        invalidate_cached_file_name(blob_key)


_DOWNLOAD_FILE_METHOD_PATH = "/api/method/frappe_azure_blob_storage.api.azure_blob.download_file"


def parse_blob_key_from_url(file_url: str) -> str | None:
    if not file_url:
        return None
    parsed = urlparse(file_url)
    if not parsed.path.endswith(_DOWNLOAD_FILE_METHOD_PATH):
        return None
    return parse_qs(parsed.query).get("file_name", [None])[0]


# Back-compat alias for the previous underscored name.
_parse_blob_key_from_url = parse_blob_key_from_url
