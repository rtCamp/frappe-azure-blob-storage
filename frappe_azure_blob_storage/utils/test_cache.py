# Copyright (c) 2025, rtCamp and Contributors
# See license.txt

from unittest.mock import MagicMock, patch

from frappe.tests.utils import FrappeTestCase

from frappe_azure_blob_storage.utils.cache import (
    FILE_NAME_CACHE_KEY_PREFIX,
    FILE_NAME_CACHE_TTL_SECONDS,
    _parse_blob_key_from_url,
    get_cached_file_name,
    invalidate_cached_file_name,
    invalidate_from_file_url,
    parse_blob_key_from_url,
    set_cached_file_name,
)


class TestDownloadFileCache(FrappeTestCase):
    """
    Unit tests for the download_file blob-key -> File.name cache helper.

    We patch `frappe.cache()` so the tests don't depend on a running Redis
    instance and can assert exact key/TTL semantics.
    """

    def test_cache_key_uses_expected_namespace(self):
        cache = MagicMock()
        cache.get_value.return_value = "FILE-0001"
        with patch("frappe_azure_blob_storage.utils.cache.frappe.cache", return_value=cache):
            get_cached_file_name("abcd1234/report.pdf")
        cache.get_value.assert_called_once_with(f"{FILE_NAME_CACHE_KEY_PREFIX}::abcd1234/report.pdf")

    def test_set_cached_file_name_uses_configured_ttl(self):
        cache = MagicMock()
        with patch("frappe_azure_blob_storage.utils.cache.frappe.cache", return_value=cache):
            set_cached_file_name("abcd1234/report.pdf", "FILE-0001")
        cache.set_value.assert_called_once_with(
            f"{FILE_NAME_CACHE_KEY_PREFIX}::abcd1234/report.pdf",
            "FILE-0001",
            expires_in_sec=FILE_NAME_CACHE_TTL_SECONDS,
        )

    def test_getters_and_setters_no_op_on_empty_inputs(self):
        cache = MagicMock()
        with patch("frappe_azure_blob_storage.utils.cache.frappe.cache", return_value=cache):
            self.assertIsNone(get_cached_file_name(""))
            set_cached_file_name("", "FILE-0001")
            set_cached_file_name("abcd1234/report.pdf", "")
            invalidate_cached_file_name("")
        cache.get_value.assert_not_called()
        cache.set_value.assert_not_called()
        cache.delete_value.assert_not_called()

    def test_invalidate_deletes_the_expected_key(self):
        cache = MagicMock()
        with patch("frappe_azure_blob_storage.utils.cache.frappe.cache", return_value=cache):
            invalidate_cached_file_name("abcd1234/report.pdf")
        cache.delete_value.assert_called_once_with(f"{FILE_NAME_CACHE_KEY_PREFIX}::abcd1234/report.pdf")

    def test_parse_blob_key_from_proxy_url(self):
        url = (
            "https://example.com/api/method/frappe_azure_blob_storage.api.azure_blob.download_file"
            "?file_name=abcd1234/report.pdf"
        )
        self.assertEqual(_parse_blob_key_from_url(url), "abcd1234/report.pdf")

    def test_parse_blob_key_returns_none_for_local_urls(self):
        self.assertIsNone(_parse_blob_key_from_url("/private/files/report.pdf"))
        self.assertIsNone(_parse_blob_key_from_url("/files/logo.png"))
        self.assertIsNone(_parse_blob_key_from_url(""))
        self.assertIsNone(_parse_blob_key_from_url(None))

    def test_invalidate_from_file_url_delegates_to_cache_delete(self):
        cache = MagicMock()
        url = (
            "https://example.com/api/method/frappe_azure_blob_storage.api.azure_blob.download_file"
            "?file_name=abcd1234/report.pdf"
        )
        with patch("frappe_azure_blob_storage.utils.cache.frappe.cache", return_value=cache):
            invalidate_from_file_url(url)
        cache.delete_value.assert_called_once_with(f"{FILE_NAME_CACHE_KEY_PREFIX}::abcd1234/report.pdf")

    def test_invalidate_from_file_url_ignores_local_urls(self):
        cache = MagicMock()
        with patch("frappe_azure_blob_storage.utils.cache.frappe.cache", return_value=cache):
            invalidate_from_file_url("/private/files/report.pdf")
            invalidate_from_file_url("")
        cache.delete_value.assert_not_called()

    def test_parse_blob_key_ignores_other_api_method_paths(self):
        """
        The parser must not accept any `/api/method/...` URL — only our
        own download_file endpoint. A stray whitelisted method URL that
        somehow surfaced in File.file_url should be treated as a miss.
        """
        url = (
            "https://example.com/api/method/frappe.core.doctype.file.file.some_other_method"
            "?file_name=abcd1234/report.pdf"
        )
        self.assertIsNone(_parse_blob_key_from_url(url))

    def test_parse_blob_key_uses_endswith_not_substring(self):
        """
        The path check is `endswith`, not `in`. A future endpoint whose
        path merely contains `.download_file` (e.g. `download_file_v2`,
        or a nested mount) must not be treated as the download_file
        proxy endpoint. This guards the (small but real) risk of a
        substring-based match accepting an unrelated method URL and
        extracting a random `file_name` from it.
        """
        # `download_file_v2` — path CONTAINS the download_file suffix
        # only if the base path ends there; here it clearly does not.
        v2_url = (
            "https://example.com/api/method/frappe_azure_blob_storage.api.azure_blob.download_file_v2"
            "?file_name=abcd1234/report.pdf"
        )
        self.assertIsNone(parse_blob_key_from_url(v2_url))

        # Nested path where download_file appears as a mid-segment.
        nested_url = (
            "https://example.com/api/method/frappe_azure_blob_storage.api.azure_blob.download_file/extra"
            "?file_name=abcd1234/report.pdf"
        )
        self.assertIsNone(parse_blob_key_from_url(nested_url))

    def test_public_and_underscored_names_are_the_same_helper(self):
        """
        `_parse_blob_key_from_url` is kept as a back-compat alias for
        `parse_blob_key_from_url`. Guard against a future refactor that
        drops the alias silently by asserting they refer to the same
        callable.
        """
        self.assertIs(_parse_blob_key_from_url, parse_blob_key_from_url)
