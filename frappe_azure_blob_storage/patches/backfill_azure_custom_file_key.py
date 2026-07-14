import frappe
from frappe.custom.doctype.custom_field.custom_field import create_custom_fields
from pypika import CustomFunction

# Mirror of BlobStore.get_formatted_file_key -> file_key[:255] and the
# custom_file_key column length. Kept as a constant because the backfill runs
# the slice in SQL (LEFT(...)) rather than in Python for performance.
MAX_KEY_LEN = 255
BATCH_SIZE = 10000

Left = CustomFunction("LEFT", ["string", "length"])
# MySQL/MariaDB: everything after the last 'file_name='.
SubstringIndex = CustomFunction("SUBSTRING_INDEX", ["string", "delim", "count"])
# Postgres equivalent: everything after the first 'file_name='.
SplitPart = CustomFunction("SPLIT_PART", ["string", "delim", "part"])


def execute():
    """Backfill ``custom_file_key`` for File records already uploaded to Azure.

    Earlier versions stored the blob key in the standard ``content_hash``
    column (a ``VARCHAR(140)`` field that silently truncated long keys). The
    download proxy now resolves files by ``custom_file_key`` instead, so any
    File already on Azure must be backfilled or it becomes undownloadable.

    The full, untruncated key is recovered from ``file_url`` -- the proxy URL
    carries it verbatim as the ``file_name`` query parameter -- which is a more
    reliable source than the truncated ``content_hash``.

    This is done as a batched set-based ``UPDATE`` (not per-row ``set_value``)
    because the target tables run into the millions of rows; the key extraction
    is pure string manipulation that the database can do far faster in bulk.

    ``custom_file_key`` is created via fixtures, which sync *after*
    post_model_sync patches run. So the column may not exist yet on the deploy
    migrate; we ensure it up front to keep this patch self-sufficient and
    safely idempotent (create_custom_fields is a no-op update if it exists).
    """
    _ensure_custom_file_key_field()

    # Nothing to backfill if the app's azure flag was never installed.
    if not frappe.db.has_column("File", "custom_uploaded_to_azure"):
        return

    File = frappe.qb.DocType("File")
    key_expr = _key_expression(File)

    # Predicate for rows still needing a backfill. Once a row is updated it no
    # longer matches, so each batch naturally picks up the next set of rows.
    pending = (
        (File.custom_uploaded_to_azure == 1)
        & (File.custom_file_key.isnull() | (File.custom_file_key == ""))
        & (File.file_url.like("%/api/method/%file_name=%"))
    )

    total = 0
    while True:
        names = (frappe.qb.from_(File).select(File.name).where(pending).limit(BATCH_SIZE)).run(pluck="name")

        if not names:
            break

        (frappe.qb.update(File).set(File.custom_file_key, key_expr).where(File.name.isin(names))).run()

        frappe.db.commit()
        total += len(names)

    if total:
        print(f"Backfilled custom_file_key for {total} Azure File record(s).")


def _key_expression(File):
    """Extract the blob key from ``file_url``'s ``file_name`` param and slice it
    to the column length, as a query-builder expression."""
    if frappe.db.db_type == "postgres":
        blob_key = SplitPart(File.file_url, "file_name=", 2)
    else:
        blob_key = SubstringIndex(File.file_url, "file_name=", -1)
    return Left(blob_key, MAX_KEY_LEN)


def _ensure_custom_file_key_field():
    if frappe.db.has_column("File", "custom_file_key"):
        return

    create_custom_fields(
        {
            "File": [
                {
                    "fieldname": "custom_file_key",
                    "label": "File Key",
                    "fieldtype": "Data",
                    "length": MAX_KEY_LEN,
                    "insert_after": "custom_uploaded_to_azure",
                    "search_index": 1,
                    "read_only": 1,
                    "translatable": 0,
                }
            ]
        }
    )
