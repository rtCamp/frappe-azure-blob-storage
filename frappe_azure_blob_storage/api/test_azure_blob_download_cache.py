# Copyright (c) 2025, rtCamp and Contributors
# See license.txt

from unittest.mock import MagicMock, patch

import frappe
from frappe.tests.utils import FrappeTestCase


class TestDownloadFileCacheWiring(FrappeTestCase):
    """
    Integration-style tests that drive `download_file` through the
    miss -> hit -> stale-docname -> stale-file_url paths and assert the
    DB / cache calls are what we expect.

    These complement the unit tests in `utils/test_cache.py` (which cover
    the cache helper in isolation) by pinning down the actual wiring in
    `api.azure_blob.download_file`.
    """

    BLOB_KEY = "abcd1234/report.pdf"
    DOCNAME = "FILE-0001"
    PROXY_URL = (
        "https://example.com/api/method/frappe_azure_blob_storage.api.azure_blob.download_file"
        f"?file_name={BLOB_KEY}"
    )

    def _make_file_doc(self, file_url=None, is_private=True, is_downloadable=True):
        doc = MagicMock()
        doc.file_url = file_url if file_url is not None else self.PROXY_URL
        doc.is_private = is_private
        doc.is_downloadable.return_value = is_downloadable
        return doc

    def _patched_download(
        self,
        cache_mock,
        get_value_mock,
        get_doc_mock,
        blob_store_mock,
    ):
        """Wire up the standard set of patches for a single call."""
        return (
            patch("frappe_azure_blob_storage.api.azure_blob.frappe.cache", return_value=cache_mock),
            patch("frappe_azure_blob_storage.utils.cache.frappe.cache", return_value=cache_mock),
            patch("frappe_azure_blob_storage.api.azure_blob.frappe.db.get_value", get_value_mock),
            patch("frappe_azure_blob_storage.api.azure_blob.frappe.get_doc", get_doc_mock),
            patch("frappe_azure_blob_storage.api.azure_blob.BlobStore", blob_store_mock),
        )

    def test_second_call_serves_from_cache_and_skips_db(self):
        """
        First call is a miss: we `db.get_value` once and populate cache.
        Second call is a hit: we do NOT hit `db.get_value` again.
        """
        from frappe_azure_blob_storage.api import azure_blob

        cache = MagicMock()
        # Simulate a live cache: miss then hit.
        cache_state = {}

        def _get(key):
            return cache_state.get(key)

        def _set(key, value, expires_in_sec=None):
            cache_state[key] = value

        def _delete(key):
            cache_state.pop(key, None)

        cache.get_value.side_effect = _get
        cache.set_value.side_effect = _set
        cache.delete_value.side_effect = _delete

        get_value = MagicMock(return_value=self.DOCNAME)
        get_doc = MagicMock(return_value=self._make_file_doc())
        blob_store = MagicMock()
        blob_store.get_file_link.return_value = self.PROXY_URL
        blob_store.is_local_file.return_value = False
        blob_store.return_value.get_private_container_name.return_value = "private"
        blob_store.return_value.generate_sas_url.return_value = "https://sas.example/"

        patches = self._patched_download(cache, get_value, get_doc, blob_store)
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            frappe.local.response = {}
            azure_blob.download_file(self.BLOB_KEY)
            azure_blob.download_file(self.BLOB_KEY)

        # First call misses, second hits the cache -> only ONE DB lookup.
        self.assertEqual(get_value.call_count, 1)

    def test_stale_docname_invalidates_cache_and_reraises(self):
        """
        If the cached docname points at a row that no longer exists,
        `download_file` must drop the cache entry and re-raise
        DoesNotExistError so the client sees a clean 404.
        """
        from frappe_azure_blob_storage.api import azure_blob

        cache = MagicMock()
        cache.get_value.return_value = self.DOCNAME  # cache hit

        get_value = MagicMock()
        get_doc = MagicMock(side_effect=frappe.DoesNotExistError)
        blob_store = MagicMock()

        patches = self._patched_download(cache, get_value, get_doc, blob_store)
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            frappe.local.response = {}
            with self.assertRaises(frappe.DoesNotExistError):
                azure_blob.download_file(self.BLOB_KEY)

        cache.delete_value.assert_called()

    def test_stale_file_url_reresolves_via_db(self):
        """
        Cache hit -> docname loads fine -> but the doc's file_url no
        longer contains the requested blob_key (out-of-band mutation).
        Handler must invalidate, re-resolve via DB, refresh the cache,
        and reload the doc.
        """
        from frappe_azure_blob_storage.api import azure_blob

        cache = MagicMock()
        cache.get_value.return_value = self.DOCNAME  # cache hit with wrong doc

        stale_doc = self._make_file_doc(file_url="/private/files/unrelated.pdf")
        fresh_doc = self._make_file_doc()

        get_value = MagicMock(return_value="FILE-0002")
        get_doc = MagicMock(side_effect=[stale_doc, fresh_doc])
        blob_store = MagicMock()
        blob_store.get_file_link.return_value = self.PROXY_URL
        blob_store.is_local_file.return_value = False
        blob_store.return_value.get_private_container_name.return_value = "private"
        blob_store.return_value.generate_sas_url.return_value = "https://sas.example/"

        patches = self._patched_download(cache, get_value, get_doc, blob_store)
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            frappe.local.response = {}
            azure_blob.download_file(self.BLOB_KEY)

        # Stale entry deleted, re-resolved via DB, re-cached, doc reloaded.
        cache.delete_value.assert_called()
        get_value.assert_called_once()
        self.assertEqual(get_doc.call_count, 2)


class TestDownloadFileCacheEviction(FrappeTestCase):
    """
    Guard the cache-invalidation contract from the doctype event side:
    a privacy flip on a File must invalidate the pre-flip proxy URL's
    cache entry BEFORE the placeholder `in-transit` URL is written via
    `frappe.db.set_value`, so a subsequent download_file for the old
    blob key does not serve a stale docname.
    """

    def test_privacy_flip_invalidates_previous_file_url_cache(self):
        from frappe_azure_blob_storage.doc_events import file as file_events

        prev_url = (
            "https://example.com/api/method/frappe_azure_blob_storage.api.azure_blob.download_file"
            "?file_name=old-key/report.pdf"
        )
        new_url_placeholder = (
            "https://example.com/api/method/frappe_azure_blob_storage.api.azure_blob.download_file"
            "?file_name=in-transit"
        )

        doc = MagicMock()
        doc.name = "FILE-0001"
        doc.file_url = prev_url  # before the placeholder rewrite
        doc.is_private = True
        doc.attached_to_doctype = None
        doc.flags = MagicMock()
        doc.flags.in_insert = False
        # Real-world privacy flip: only `is_private` changed. `file_url`
        # is still the pre-flip proxy URL and has_value_changed("file_url")
        # is False — so the top-of-hook invalidator does NOT fire, and the
        # belt-and-braces invalidate call before the raw SQL write is the
        # only thing that drops the stale cache entry.
        doc.has_value_changed.side_effect = lambda field: field == "is_private"
        doc.get_doc_before_save.return_value = None

        invalidate = MagicMock()

        with (
            patch(
                "frappe_azure_blob_storage.doc_events.file.invalidate_from_file_url",
                invalidate,
            ),
            patch("frappe_azure_blob_storage.doc_events.file.frappe.get_single") as get_single,
            patch("frappe_azure_blob_storage.doc_events.file.BlobStore") as blob_store_cls,
            patch("frappe_azure_blob_storage.doc_events.file.frappe.db.set_value"),
            patch("frappe_azure_blob_storage.doc_events.file.frappe.enqueue"),
        ):
            get_single.return_value.auto_upload_to_azure = True
            blob_store_cls.is_local_file.return_value = False
            blob_store_cls.return_value.is_ignored_dtype.return_value = False
            blob_store_cls.return_value.parse_url.return_value = "old-key/report.pdf"
            blob_store_cls.return_value.get_file_link.return_value = new_url_placeholder

            file_events.on_update(doc, method="on_update")

        # Both the pre-flip URL and the (unchanged-so-far) doc.file_url
        # get invalidated before the placeholder is written.
        invalidated_urls = [call.args[0] for call in invalidate.call_args_list]
        self.assertIn(prev_url, invalidated_urls)
