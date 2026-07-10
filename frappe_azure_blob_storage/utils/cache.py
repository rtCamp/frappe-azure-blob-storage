from urllib.parse import parse_qs, urlparse

import frappe

# Redis cache namespace for the `blob_key -> File.name` lookup used by
# `frappe_azure_blob_storage.api.azure_blob.download_file`.
#
# Why this exists:
# The `download_file` proxy resolves a request by its `file_name` argument
# (the blob key) to the underlying `tabFile` row. The default index on
# `tabFile.file_url` in Frappe core is a prefix index on the first 100
# characters, but every proxy URL we generate shares a long common prefix
# (`<site>/api/method/frappe_azure_blob_storage.api.azure_blob.download_file?file_name=...`),
# so the prefix index has near-zero selectivity and MySQL falls back to a
# scan. On high-traffic sites this dominates request latency.
#
# Caching the resolved `File.name` per blob key in Redis lets us skip the DB
# lookup entirely on cache hits, and the fallback path uses a single
# `db.get_value` instead of `db.exists` + `db.get_doc` (two round-trips).
FILE_NAME_CACHE_KEY_PREFIX = "azure_dl_file_name"
FILE_NAME_CACHE_TTL_SECONDS = 60 * 60  # 1 hour


def _build_cache_key(blob_key: str) -> str:
    return f"{FILE_NAME_CACHE_KEY_PREFIX}::{blob_key}"


def get_cached_file_name(blob_key: str) -> str | None:
    """
    Return the cached `File.name` (docname) for the given blob key, or None.
    """
    if not blob_key:
        return None
    return frappe.cache().get_value(_build_cache_key(blob_key))


def set_cached_file_name(blob_key: str, file_name: str) -> None:
    """
    Cache the `blob_key -> File.name` mapping with a bounded TTL.
    """
    if not blob_key or not file_name:
        return
    frappe.cache().set_value(
        _build_cache_key(blob_key),
        file_name,
        expires_in_sec=FILE_NAME_CACHE_TTL_SECONDS,
    )


def invalidate_cached_file_name(blob_key: str) -> None:
    """
    Drop the cache entry for a specific blob key. Safe to call with an
    empty/None key (no-op).
    """
    if not blob_key:
        return
    frappe.cache().delete_value(_build_cache_key(blob_key))


def invalidate_from_file_url(file_url: str) -> None:
    """
    Invalidate the cache entry derived from a File document's `file_url`.

    We deliberately do the URL parsing inline (instead of instantiating
    `BlobStore`) because this runs from doc-event hooks on every File save
    and `BlobStore.__init__` loads `Azure Storage Settings` from the DB.
    """
    blob_key = parse_blob_key_from_url(file_url)
    if blob_key:
        invalidate_cached_file_name(blob_key)


_DOWNLOAD_FILE_METHOD_PATH = "/api/method/frappe_azure_blob_storage.api.azure_blob.download_file"


def parse_blob_key_from_url(file_url: str) -> str | None:
    """
    Extract the `file_name` query parameter from our proxy URL. Returns
    None for local URLs, other whitelisted endpoints, or anything
    unparseable.

    Path matching is done with `endswith` (rather than a substring `in`
    test) so a hypothetical future endpoint whose path merely CONTAINS
    `.download_file` — e.g. `download_file_v2` or a mounted sub-path —
    is not accepted. Frappe method URLs never have a suffix past the
    method name, so an exact-tail match is the right primitive.

    NOTE: `parse_qs` decodes URL-encoded values, so a `file_name` query
    param containing `%20` etc. is decoded correctly. Blob keys emitted
    by the default `BlobStore.blob_key_generator` are already scrubbed
    to `[0-9a-zA-Z._-]` and are safe. Callers who install a custom
    `blob_key_generator` MUST emit URL-safe keys (or URL-encode any
    unsafe characters themselves): `get_file_link` embeds the key into
    the `file_name` query string without additional escaping, so a
    generator that emits a raw `&`, `?`, `=`, `#`, or `+` will produce
    a `file_url` that `parse_qs` splits/decodes incorrectly. The
    stale-guard in `download_file` would then always mismatch, silently
    defeating the cache for that File.
    """
    if not file_url:
        return None
    parsed = urlparse(file_url)
    if not parsed.path.endswith(_DOWNLOAD_FILE_METHOD_PATH):
        return None
    return parse_qs(parsed.query).get("file_name", [None])[0]


# Back-compat alias for the previous underscored name. Kept so external
# callers (and older tests) don't break, but new code should import the
# public name above.
_parse_blob_key_from_url = parse_blob_key_from_url
