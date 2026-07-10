# Copyright (c) 2025, rtCamp and Contributors
# See license.txt

from unittest.mock import MagicMock, patch

import frappe
from frappe.tests.utils import FrappeTestCase

from frappe_azure_blob_storage.utils.cache import _build_cache_key


class TestDownloadFileCacheWiring(FrappeTestCase):
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
        return (
            patch("frappe_azure_blob_storage.api.azure_blob.frappe.cache", return_value=cache_mock),
            patch("frappe_azure_blob_storage.utils.cache.frappe.cache", return_value=cache_mock),
            patch("frappe_azure_blob_storage.api.azure_blob.frappe.db.get_value", get_value_mock),
            patch("frappe_azure_blob_storage.api.azure_blob.frappe.get_doc", get_doc_mock),
            patch("frappe_azure_blob_storage.api.azure_blob.BlobStore", blob_store_mock),
        )

    def test_second_call_serves_from_cache_and_skips_db(self):
        from frappe_azure_blob_storage.api import azure_blob

        cache = MagicMock()
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

        self.assertEqual(get_value.call_count, 1)
        self.assertEqual(cache.get_value.call_count, 2)
        self.assertEqual(cache.set_value.call_count, 1)

    def test_fid_variants_share_cache_entry(self):
        from frappe_azure_blob_storage.api import azure_blob

        cache = MagicMock()
        cache_state = {}
        cache.get_value.side_effect = lambda key: cache_state.get(key)
        cache.set_value.side_effect = lambda key, value, expires_in_sec=None: cache_state.__setitem__(key, value)
        cache.delete_value.side_effect = lambda key: cache_state.pop(key, None)

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
            azure_blob.download_file(f"{self.BLOB_KEY}?fid=req-A")
            azure_blob.download_file(f"{self.BLOB_KEY}?fid=req-B")

        self.assertEqual(get_value.call_count, 1)
        self.assertEqual(cache.set_value.call_count, 1)
        set_key = cache.set_value.call_args_list[0].args[0]
        self.assertEqual(set_key, _build_cache_key(self.BLOB_KEY))

    def test_stale_docname_invalidates_cache_and_reraises(self):
        from frappe_azure_blob_storage.api import azure_blob

        cache = MagicMock()
        cache.get_value.return_value = self.DOCNAME

        get_value = MagicMock()
        get_doc = MagicMock(side_effect=frappe.DoesNotExistError)
        blob_store = MagicMock()

        patches = self._patched_download(cache, get_value, get_doc, blob_store)
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            frappe.local.response = {}
            with self.assertRaises(frappe.DoesNotExistError):
                azure_blob.download_file(self.BLOB_KEY)

        cache.delete_value.assert_called_once_with(_build_cache_key(self.BLOB_KEY))

    def test_stale_file_url_reresolves_via_db(self):
        from frappe_azure_blob_storage.api import azure_blob

        cache = MagicMock()
        cache.get_value.return_value = self.DOCNAME

        # stale_doc.file_url points at an unrelated proxy URL (not a
        # /private/files/... path) so parse_blob_key_from_url returns a
        # real key and the exact-equality guard has a meaningful mismatch.
        stale_doc = self._make_file_doc(
            file_url=(
                "https://example.com/api/method/frappe_azure_blob_storage.api.azure_blob.download_file"
                "?file_name=unrelated-key/other.pdf"
            )
        )
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

        cache.delete_value.assert_called_once_with(_build_cache_key(self.BLOB_KEY))
        get_value.assert_called_once()
        self.assertEqual(get_doc.call_count, 2)


class TestDownloadFileCacheEviction(FrappeTestCase):
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
        doc.file_url = prev_url
        doc.is_private = True
        doc.attached_to_doctype = None
        doc.flags = MagicMock()
        doc.flags.in_insert = False
        # Privacy-flip only: has_value_changed("file_url") is False, so the
        # top-of-hook invalidator does not fire — only the pre-SQL invalidate.
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

        invalidated_urls = [call.args[0] for call in invalidate.call_args_list]
        self.assertIn(prev_url, invalidated_urls)

    def test_privacy_flip_invalidates_prev_url_twice_to_shrink_race_window(self):
        from frappe_azure_blob_storage.doc_events import file as file_events

        prev_url = (
            "https://example.com/api/method/frappe_azure_blob_storage.api.azure_blob.download_file"
            "?file_name=old-key/report.pdf"
        )
        placeholder = (
            "https://example.com/api/method/frappe_azure_blob_storage.api.azure_blob.download_file"
            "?file_name=in-transit"
        )

        doc = MagicMock()
        doc.name = "FILE-0001"
        doc.file_url = prev_url
        doc.is_private = True
        doc.attached_to_doctype = None
        doc.flags = MagicMock()
        doc.flags.in_insert = False
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
            blob_store_cls.return_value.get_file_link.return_value = placeholder

            file_events.on_update(doc, method="on_update")

        invalidated_urls = [call.args[0] for call in invalidate.call_args_list]
        self.assertGreaterEqual(invalidated_urls.count(prev_url), 2)


class TestAfterRenameInvalidatesCache(FrappeTestCase):
    def test_after_rename_invalidates_cache_by_current_file_url(self):
        from frappe_azure_blob_storage.doc_events import file as file_events

        proxy_url = (
            "https://example.com/api/method/frappe_azure_blob_storage.api.azure_blob.download_file"
            "?file_name=some-key/report.pdf"
        )
        doc = MagicMock()
        doc.file_url = proxy_url

        invalidate = MagicMock()

        with patch(
            "frappe_azure_blob_storage.doc_events.file.invalidate_from_file_url",
            invalidate,
        ):
            file_events.after_rename(
                doc,
                method="after_rename",
                old_name="OLD",
                new_name="NEW",
                merge=False,
            )

        invalidate.assert_called_once_with(proxy_url)


class TestDownloadFileWhitespaceStripping(FrappeTestCase):
    BLOB_KEY = "abcd1234/report.pdf"
    DOCNAME = "FILE-0001"
    PROXY_URL = (
        "https://example.com/api/method/frappe_azure_blob_storage.api.azure_blob.download_file"
        f"?file_name={BLOB_KEY}"
    )

    def _make_file_doc(self):
        doc = MagicMock()
        doc.file_url = self.PROXY_URL
        doc.is_private = True
        doc.is_downloadable.return_value = True
        return doc

    def test_trailing_whitespace_does_not_leak_into_cache_key(self):
        from frappe_azure_blob_storage.api import azure_blob

        cache = MagicMock()
        cache_state = {}
        cache.get_value.side_effect = lambda key: cache_state.get(key)
        cache.set_value.side_effect = lambda key, value, expires_in_sec=None: cache_state.__setitem__(key, value)
        cache.delete_value.side_effect = lambda key: cache_state.pop(key, None)

        get_value = MagicMock(return_value=self.DOCNAME)
        get_doc = MagicMock(return_value=self._make_file_doc())
        blob_store = MagicMock()
        blob_store.get_file_link.return_value = self.PROXY_URL
        blob_store.is_local_file.return_value = False
        blob_store.return_value.get_private_container_name.return_value = "private"
        blob_store.return_value.generate_sas_url.return_value = "https://sas.example/"

        with (
            patch("frappe_azure_blob_storage.api.azure_blob.frappe.cache", return_value=cache),
            patch("frappe_azure_blob_storage.utils.cache.frappe.cache", return_value=cache),
            patch("frappe_azure_blob_storage.api.azure_blob.frappe.db.get_value", get_value),
            patch("frappe_azure_blob_storage.api.azure_blob.frappe.get_doc", get_doc),
            patch("frappe_azure_blob_storage.api.azure_blob.BlobStore", blob_store),
        ):
            frappe.local.response = {}
            azure_blob.download_file(f"  {self.BLOB_KEY}  ")

        self.assertEqual(cache.set_value.call_count, 1)
        set_key = cache.set_value.call_args_list[0].args[0]
        self.assertEqual(set_key, _build_cache_key(self.BLOB_KEY))

    def test_whitespace_only_input_raises_does_not_exist_and_skips_cache_write(self):
        from frappe_azure_blob_storage.api import azure_blob

        cache = MagicMock()
        cache.get_value.return_value = None

        get_value = MagicMock(return_value=None)
        get_doc = MagicMock()
        blob_store = MagicMock()
        blob_store.get_file_link.return_value = (
            "https://example.com/api/method/frappe_azure_blob_storage.api.azure_blob.download_file?file_name="
        )
        blob_store.is_local_file.return_value = False

        with (
            patch("frappe_azure_blob_storage.api.azure_blob.frappe.cache", return_value=cache),
            patch("frappe_azure_blob_storage.utils.cache.frappe.cache", return_value=cache),
            patch("frappe_azure_blob_storage.api.azure_blob.frappe.db.get_value", get_value),
            patch("frappe_azure_blob_storage.api.azure_blob.frappe.get_doc", get_doc),
            patch("frappe_azure_blob_storage.api.azure_blob.BlobStore", blob_store),
        ):
            frappe.local.response = {}
            with self.assertRaises(frappe.DoesNotExistError):
                azure_blob.download_file("   ")

        cache.set_value.assert_not_called()
        get_doc.assert_not_called()


class TestChangeFilePrivacyRollbackInvalidatesCache(FrappeTestCase):
    def test_rollback_invalidates_transient_and_prev_url(self):
        from frappe_azure_blob_storage.blob_controllers import blob_store as bs_mod

        prev_url = (
            "https://example.com/api/method/frappe_azure_blob_storage.api.azure_blob.download_file"
            "?file_name=old-key/report.pdf"
        )
        transient_url = (
            "https://example.com/api/method/frappe_azure_blob_storage.api.azure_blob.download_file"
            "?file_name=in-transit"
        )

        file_doc = MagicMock()
        file_doc.custom_uploaded_to_azure = True

        # Force the try-block body to raise so we exercise the except branch.
        blob_store_instance = MagicMock()
        blob_store_instance.get_private_container_name.return_value = "private"
        blob_store_instance.get_public_container_name.return_value = "public"
        blob_store_instance.parse_url.return_value = "old-key/report.pdf"
        blob_store_instance.get_file_link.return_value = transient_url
        blob_store_instance.blob_service_client.get_blob_client.side_effect = RuntimeError("boom")

        invalidate = MagicMock()

        with (
            patch.object(bs_mod, "BlobStore", return_value=blob_store_instance),
            patch.object(bs_mod, "invalidate_from_file_url", invalidate),
            patch.object(bs_mod.frappe, "get_doc", return_value=file_doc),
            patch.object(bs_mod.frappe.db, "set_value"),
            patch.object(bs_mod.frappe.db, "commit"),
            patch.object(bs_mod, "generate_error_log"),
        ):
            try:
                bs_mod.change_file_privacy(file_id="FILE-0001", to_private=True, prev_url=prev_url)
            except Exception:
                pass

        invalidated = [call.args[0] for call in invalidate.call_args_list]
        self.assertIn(transient_url, invalidated)
        self.assertIn(prev_url, invalidated)
