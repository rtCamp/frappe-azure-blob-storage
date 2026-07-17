<div align="center">

<!-- LOGO: replace the line below with your logo, e.g. <img src="docs/logo.png" alt="Frappe Azure Blob Storage" width="180"/> -->
<!-- ![Frappe Azure Blob Storage](docs/logo.png) -->

# Frappe Azure Blob Storage

**Offload your files  to Azure Blob Storage — automatically, securely, and without changing how your users work with files.**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Frappe](https://img.shields.io/badge/Frappe-v16-0089ff.svg)](https://frappeframework.com)
[![Azure](https://img.shields.io/badge/Azure-Blob%20Storage-0078d4.svg)](https://azure.microsoft.com/en-us/products/storage/blobs)

</div>

---

## Overview

**Frappe Azure Blob Storage** moves file attachments in your Frappe site from local disk to [Azure Blob Storage](https://azure.microsoft.com/en-us/products/storage/blobs). Once installed and configured, every file a user uploads is automatically pushed to Azure, while downloads are served securely through short-lived SAS (Shared Access Signature) URLs.

There is **no change to the end-user experience** — users upload and download files exactly as before. Under the hood, your Frappe server stops accumulating files on its local volume, and private files are never exposed publicly.

## Features

- **Automatic upload** — New file attachments are pushed to Azure Blob Storage on creation, with no manual step.
- **Public & private containers** — Public and private files are segregated into two separate containers (`<name>-frappe-public` and `<name>-frappe-private`), preserving Frappe's privacy model.
- **Secure downloads via SAS URLs** — Private files are served through time-limited, read-only SAS tokens. Permissions are re-checked on every request through a Frappe proxy endpoint, so access control is never bypassed.
- **SAS URL caching** — Generated SAS URLs are cached (minus a safety margin before expiry) to avoid regenerating tokens on every download.
- **Privacy transitions handled automatically** — Toggling a file between public and private performs a server-side copy between containers in a background job — no re-upload of file bytes.
- **Bulk migration** — Migrate existing local files to Azure in bulk, either from the UI (**Migrate Files** button) or via a bench CLI command. Migration runs as paginated background jobs with live progress.
- **Flexible authentication** — Connect using either an Azure **Connection String** or a **Storage Account Name + Access Key**.
- **Ignore specific DocTypes** — Exclude chosen DocTypes from being offloaded to Azure.
- **Optional local cleanup** — Optionally delete the original file from local storage after a successful upload to reclaim disk space.
- **Custom key generator hook** — Override how blob keys/paths are generated via an app hook, to fit your own container layout.
- **Regional / sovereign cloud support** — Configurable endpoint suffix for national or regional Azure clouds.

## How It Works

```
┌───────────────┐   upload    ┌────────────────────────┐   put blob    ┌──────────────────────┐
│ User uploads   │ ──────────▶ │  Frappe File document   │ ────────────▶ │  Azure Blob Storage   │
│ a file         │             │  (before_insert hook)   │               │  private / public     │
└───────────────┘             └────────────────────────┘               │  containers           │
                                        │                               └──────────────────────┘
                                        │  file_url rewritten to
                                        ▼  /api/method/...download_file?file_name=<key>
┌───────────────┐  download   ┌────────────────────────┐  redirect     ┌──────────────────────┐
│ User clicks    │ ──────────▶ │  download_file proxy    │ ────────────▶ │  short-lived SAS URL  │
│ the file       │             │  (permission check)     │               │  (read-only)          │
└───────────────┘             └────────────────────────┘               └──────────────────────┘
```

1. **Upload** — When a `File` document is created, a `before_insert` hook uploads the file bytes to the appropriate Azure container (public or private) under a generated blob key. The document's `file_url` is rewritten to point at a Frappe proxy endpoint, and the blob key is stored in an indexed `custom_file_key` field for fast lookups.

2. **Download** — The proxy endpoint `frappe_azure_blob_storage.api.azure_blob.download_file` looks up the file by its key, **re-checks the user's permission**, generates (or reuses a cached) SAS URL, and redirects the browser to it. Private files are therefore only reachable by users who are actually allowed to see them.

3. **Privacy change** — When a file's `is_private` flag changes, an `on_update` hook enqueues a background job that performs a **server-side copy** from the source container to the destination container, then deletes the original — no file content passes through the Frappe server.

4. **Deletion** — When a `File` is trashed, the corresponding blob is deleted from Azure on a best-effort basis.

5. **Containers are created lazily** — Containers are only created the first time a write actually needs them, avoiding unnecessary Azure round-trips on read-heavy workloads.

## Installation

Install using the [bench](https://github.com/frappe/bench) CLI:

```bash
cd $PATH_TO_YOUR_BENCH

# Fetch the app
bench get-app https://github.com/rtCamp/frappe-azure-blob-storage --branch develop

# Install it on your site
bench --site your-site.local install-app frappe_azure_blob_storage
```

> **Requirements:** Frappe v16+ and Python 3.14+. The app depends on `azure-storage-blob`, `azure-identity`, and `python-magic` (installed automatically by bench).

## Configuration

All configuration lives in the **Azure Storage Settings** single DocType (search for it in the Frappe desk).

| Setting | Description |
| --- | --- |
| **Authentication Method** | `Connection String` or `Access Key`. |
| **Connection String** | Azure Storage connection string (used with the Connection String method). |
| **Storage Account Name** / **Access Key** | Credentials used with the Access Key method. |
| **Endpoint Suffix** | Usually `blob.core.windows.net`; change for national/regional clouds. |
| **Default Container Name** | Base name; `-frappe-public` and `-frappe-private` are appended to form the two containers. |
| **Auto Upload to Azure** | Master switch — when off, files stay on local disk. |
| **Remove Original Files** | Delete the local copy after a successful upload. |
| **SAS Token Validity** | Lifetime (in seconds) of generated SAS download URLs. Default `900`. |
| **Ignored DocTypes** | DocTypes whose attachments should *not* be offloaded to Azure. |

After entering credentials, use the **Check Connection** button to verify connectivity before enabling auto-upload.

## Migrating Existing Files

To move files that already live on local disk into Azure:

**From the UI** — Open **Azure Storage Settings** and click **Migrate Files**. Migration runs in the background with a live progress indicator.

**From the CLI** — Run the bundled bench command:

```bash
bench --site your-site.local migrate-azure-files
```

Both paths process eligible local files (those not already on Azure and not matching an ignored DocType) in batches.

## Customization

### Custom blob key generator

To control how blob keys/paths are generated, register a `blob_key_generator` hook in your own app's `hooks.py`:

```python
# your_app/hooks.py
blob_key_generator = "your_app.utils.generate_blob_key"
```

```python
# your_app/utils.py
def generate_blob_key(file_name, parent_doctype=None, parent_name=None):
    # Return a custom key/path (leading/trailing slashes are stripped)
    return f"{parent_doctype}/{file_name}"
```

If the hook returns a falsy value or raises, the app falls back to its default key generator (an 8-character hash prefix plus the sanitized file name).

## Contributing

This app uses `pre-commit` for code formatting and linting. Please [install pre-commit](https://pre-commit.com/#installation) and enable it for this repository:

```bash
cd apps/frappe_azure_blob_storage
pre-commit install
```

Pre-commit is configured to use the following tools:

- [ruff](https://github.com/astral-sh/ruff)
- [eslint](https://eslint.org/)
- [prettier](https://prettier.io/)
- [pyupgrade](https://github.com/asottile/pyupgrade)

## License

[AGPL-3.0](license.txt)

---

<div align="center">
Made with ❤️ by <a href="https://rtcamp.com/">rtCamp</a>
</div>
