import frappe
from frappe import _

from frappe_azure_blob_storage.blob_controllers.blob_store import BlobStore, upload_local_file
from frappe_azure_blob_storage.utils.cache import (
    get_cached_file_name,
    invalidate_cached_file_name,
    parse_blob_key_from_url,
    set_cached_file_name,
)
from frappe_azure_blob_storage.utils.error import generate_error_log
from frappe_azure_blob_storage.utils.http import http_response


@frappe.whitelist(methods=["GET"])
def test_connection():
    """
    Test the connection to Azure Blob Storage using the credentials
    stored in 'Azure Storage Settings'.
    """
    try:
        settings = frappe.get_single("Azure Storage Settings")
        if not settings:
            return http_response("Azure Storage Settings not found.")

        blob_store = BlobStore()
        blob_store.blob_service_client.get_service_properties()  # This will raise an error if connection fails

        return http_response(_("Connection to Azure Blob Storage is successful."))

    except Exception as e:
        return http_response(
            _("Failed to connect to Azure Blob Storage: {}").format(str(e)),
            success=False,
        )


@frappe.whitelist(methods=["GET"])
def migrate_files():
    """
    Migrate files from local storage to Azure Blob Storage.
    This function assumes that the files are stored in a specific directory
    and uploads them to the configured Azure Blob Storage container.
    """
    try:
        page_idx = 0
        page_size = 100

        while True:
            files_list = frappe.get_all(
                "File",
                fields=["name", "file_url", "file_name"],
                filters=BlobStore.AZURE_FILE_FILTERS,
                limit_start=(page_idx * page_size),
                limit_page_length=page_size,
                order_by="creation asc",
            )
            if not files_list:
                # If no files are found in the first place, we can return
                if page_idx == 0:
                    return http_response(success=False, message=_("No new local files to migrate."))

                break

            frappe.enqueue(
                _run_migrate_job,
                queue="long",
                job_id=f"migrate_files_to_azure-part_{page_idx}",
                deduplicate=True,
                is_web_request=True,
                files_list=files_list,
            )
            page_idx += 1

        return http_response(_("File migration to Azure Blob Storage has been queued successfully."))

    except Exception as e:
        return http_response(
            _("Failed to migrate files to Azure Blob Storage: {}").format(str(e)),
            success=False,
        )


def _run_migrate_job(files_list: list | None = None, is_web_request: bool = True):
    """
    Migrate files from local storage to Azure Blob Storage.
    This function assumes that the files are stored in a specific directory
    and uploads them to the configured Azure Blob Storage container.
    """

    try:
        if files_list is None:
            files_list = frappe.get_all(
                "File",
                fields=["name", "file_url", "file_name"],
                filters=BlobStore.AZURE_FILE_FILTERS,
            )
        total_files = len(files_list)
        if not total_files:
            if not is_web_request:
                print("No new local files to migrate.")
            return

        for index, file in enumerate(files_list):
            file_id = file["name"]
            file_name = file["file_name"]
            try:
                upload_local_file(file_id=file_id)
            except FileNotFoundError:
                generate_error_log(
                    "File Migration Error",
                    f"File not found on local disk: {file_id}:{file_name}. Skipping.",
                )
                if is_web_request:
                    frappe.publish_progress(
                        100,
                        title=_("Azure File Migration"),
                        description=_("File not found: {0}. Skipping.").format(file_name),
                    )
                else:
                    print(
                        f"File not found on local disk: {file_id}:{file_name}. Skipping.",
                    )
                continue
            current_file_number = index + 1
            # Update progress
            progress = current_file_number / total_files * 100
            description = _("Migrating {0}/{1}: {2}").format(current_file_number, total_files, file_name)
            if is_web_request:
                frappe.publish_progress(
                    progress,
                    title=_("Azure File Migration"),
                    description=description,
                )
            else:
                print(description)
        # Final progress update to signify completion
        if is_web_request:
            frappe.publish_progress(
                100,
                title=_("Azure File Migration"),
                description=_("Migration completed successfully!"),
            )
            frappe.msgprint(
                _("File migration to Azure Blob Storage completed successfully."),
                realtime=True,
            )
        else:
            print("Migration completed successfully!")

    except Exception as e:
        generate_error_log(
            "Azure Blob Storage Migration Error",
            frappe.get_traceback(),
            exception=e,
        )
        if is_web_request:
            frappe.msgprint(
                _("Failed to migrate files to Azure Blob Storage"),
                realtime=True,
            )
        else:
            print(f"\nERROR: Migration failed. Check Error Log for details.\n{frappe.get_traceback()}")


def _resolve_and_cache_file_doc(file_name: str) -> "frappe.model.document.Document":
    """
    Resolve a blob key to a fully-loaded `File` document via a single
    `db.get_value` + `get_doc`, populating the blob-key -> docname cache
    on the way. Raises `frappe.DoesNotExistError` if no row matches.

    Shared by both the cache-miss path and the stale-guard re-resolution
    path in `download_file` so the two branches stay in lockstep.

    Cache write is deferred until AFTER `get_doc` returns successfully:
    a get_doc failure between the `db.get_value` and the load (row
    deleted mid-flight, child-table load error, permission surface, etc.)
    must not leave a docname in the cache that can't actually be loaded.
    The `download_file` DoesNotExistError branch self-heals eventually,
    but we don't want concurrent readers piling onto a poisoned entry.
    """
    file_url = BlobStore.get_file_link(file_name)
    docname = frappe.db.get_value("File", {"file_url": file_url}, "name")
    if not docname:
        raise frappe.DoesNotExistError
    file_doc = frappe.get_doc("File", docname)
    set_cached_file_name(file_name, docname)
    return file_doc


@frappe.whitelist(methods=["GET"], allow_guest=True)  # nosemgrep
def download_file(file_name: str):
    from frappe.utils.response import download_private_file

    """
    A proxy method to securely download private files from Azure.
    It checks file permissions and then redirects to a temporary SAS URL.
    """
    try:
        # --- Strip the ?fid=... query parameter ---
        # This ensures we get the clean file path from the URL.
        if "?fid=" in file_name:
            file_name = file_name.split("?fid=")[0]

        # Defensive hardening against malformed clients that append a
        # stray leading/trailing space. Blob keys emitted by the default
        # `BlobStore.blob_key_generator` are scrubbed to `[0-9a-zA-Z._-]`
        # and cannot legitimately contain whitespace, so this strip is
        # safe. A custom `blob_key_generator` hook that emits whitespace
        # would collide with the DB row anyway (MySQL trailing-space
        # collation), so normalizing here matches DB semantics.
        file_name = file_name.strip()

        # 1. Resolve the File docname.
        #
        # High-traffic downloads make this lookup the hot path. The core
        # `file_url_index` on `tabFile.file_url` is a prefix index on the
        # first 100 chars, and every proxy URL we mint shares a long common
        # prefix — so the index has near-zero selectivity and MySQL scans.
        #
        # We cache the resolved `File.name` per blob key in Redis; on a miss
        # we do a single `db.get_value` (previous code did `db.exists` then
        # `get_doc`, i.e. two round-trips) and populate the cache.
        docname = get_cached_file_name(file_name)
        # `docname is None` is treated as a miss because `set_cached_file_name`
        # refuses to store None/empty (see utils/cache.py) — so a None here
        # cannot mean "a legitimate cached None"; it can only be a Redis miss.
        # If a future refactor ever caches None, this branch will need to
        # distinguish miss-vs-cached-None (e.g. via a sentinel).
        if docname is None:
            file_doc = _resolve_and_cache_file_doc(file_name)
        else:
            try:
                file_doc = frappe.get_doc("File", docname)
            except frappe.DoesNotExistError:
                # The cached docname points at a row that no longer exists
                # (e.g. deleted between cache write and this request).
                # Drop the stale entry and let the client retry.
                invalidate_cached_file_name(file_name)
                raise

            # Guard against a stale cache entry where the docname still
            # exists but its file_url has been mutated out-of-band (data
            # migration, bulk-rename tool that bypasses doc events, etc.).
            # Our hooks cover the ORM paths, but Redis is a cache, not a
            # source of truth — parsing the blob key out of the doc's
            # file_url and comparing for EXACT equality (rather than a
            # substring `in` test) makes this guard prefix-safe: two blob
            # keys sharing a prefix, or a filename that happens to be a
            # substring of an unrelated URL, will no longer pass through.
            if parse_blob_key_from_url(file_doc.file_url or "") != file_name:
                invalidate_cached_file_name(file_name)
                file_doc = _resolve_and_cache_file_doc(file_name)

        # 3. If file is local let frappe handle it.
        if BlobStore.is_local_file(file_doc.file_url):
            return download_private_file(file_doc.file_url)

        if not file_doc.is_downloadable():
            raise frappe.PermissionError

        # 4. Generate the SAS URL
        blob_store = BlobStore()

        if file_doc.is_private:
            container_name = blob_store.get_private_container_name()
        else:
            container_name = blob_store.get_public_container_name()

        # The blob_name is the cleaned file_name from the start of the function
        sas_url = blob_store.generate_sas_url(blob_name=file_name, container_name=container_name)

        # 5. Redirect the user to the temporary URL
        frappe.local.response["type"] = "redirect"
        frappe.local.response["location"] = sas_url

    except (frappe.DoesNotExistError, frappe.PermissionError):
        raise
    except Exception:
        frappe.log_error(title="Private File Download", message=frappe.get_traceback())
        frappe.throw(_("Something went wrong while downloading the file."))
