### Frappe Azure Blob Storage

Blob Storage support for Azure

### Installation

You can install this app using the [bench](https://github.com/frappe/bench) CLI:

```bash
cd $PATH_TO_YOUR_BENCH
bench get-app $URL_OF_THIS_REPO --branch develop
bench install-app frappe_azure_blob_storage
```

### Contributing

This app uses `pre-commit` for code formatting and linting. Please [install pre-commit](https://pre-commit.com/#installation) and enable it for this repository:

```bash
cd apps/frappe_azure_blob_storage
pre-commit install
```

Pre-commit is configured to use the following tools for checking and formatting your code:

- ruff
- eslint
- prettier
- pyupgrade

### How `download_file` works

Uploaded files are stored on Azure with a randomised blob key; the URL saved on the Frappe `File` doc is a proxy that points back at this app:

```
<site>/api/method/frappe_azure_blob_storage.api.azure_blob.download_file?file_name=<blob-key>
```

On each request the endpoint resolves the blob key to the underlying `File` document, runs Frappe's permission check, then redirects the client to a short-lived Azure SAS URL. Because every proxy URL shares a long common prefix, the core prefix index on `tabFile.file_url` has poor selectivity — the resolved `blob-key -> File.name` mapping is therefore cached in Redis (1 hour TTL) and invalidated automatically on File update/rename/delete.

### License

agpl-3.0
