import click

from frappe_azure_blob_storage.api.azure_blob import _run_migrate_job

from .site import init_site_decorate


@click.command("migrate-azure-files")
@init_site_decorate
def migrate_azure_files():
    _run_migrate_job(is_web_request=False)
