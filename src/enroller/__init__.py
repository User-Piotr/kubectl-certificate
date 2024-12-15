import enroller.utils as utils
import typer
from enroller.certs import CertificateLoader
from enroller.data import UserData
from enroller.secrets import KubernetesSecretOperator
from enroller.version import __version__
from typing_extensions import Annotated

app = typer.Typer(no_args_is_help=True, rich_markup_mode="markdown")


def __version_callback(value: bool):
    if value:
        utils.console.print(f"CLI Version: {__version__}")
        raise typer.Exit()


def __debug_callback() -> None:
    """
    Enable the debug mode.
    """
    import debugpy

    debugpy.listen(5678)
    debugpy.wait_for_client()
    debugpy.breakpoint()


@app.callback(
    epilog="Made by \033[1;35mPiotr\033[0m :rocket: with passion \033[1;31m:heart:\033[0m"  # noqa
)
def callback(
    ctx: typer.Context,
    debug: Annotated[
        bool,
        typer.Option(
            "-debug",
            "--debug",
            help="Enable debug mode",
            rich_help_panel="Utility",
            show_default=False,
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option(
            "-verbose",
            "--verbose",
            help="Enable verbose mode",
            rich_help_panel="Utility",
            show_default=False,
        ),
    ] = False,
    version: Annotated[
        bool,
        typer.Option(
            "-version",
            "--version",
            help="Display the CLI version",
            rich_help_panel="Utility",
            callback=__version_callback,
            is_eager=True,
        ),
    ] = None,
):
    """
    **kubectl** enroller - A CLI tool to manage Kubernetes secrets,
        that use a specific certificate. :lock:

    * **List** - List Kubernetes secrets that use the specified certificate. :book:

    * **Patch** - Patch Kubernetes secrets that use the specified certificate. :hammer:

    ---

    """

    # ctx.obj = Parameters(verbose=verbose)
    ctx.obj = UserData(debug=debug, verbose=verbose)

    if debug:
        utils.console.print("Debug mode enabled", style="bold yellow")
    if verbose:
        utils.console.print("Verbose mode enabled", style="bold yellow")


@app.command(
    rich_help_panel="Commands",
    epilog="Made by \033[1;35mPiotr\033[0m :rocket: with passion \033[1;31m:heart:\033[0m",  # noqa
)
def list(
    ctx: typer.Context,
    cert: Annotated[
        str,
        typer.Option(
            "-cert",
            "--cert",
            help="Path to the TLS certificate file",
            rich_help_panel="Arguments",
            show_default=False,
            callback=utils.validate_path,
        ),
    ],
) -> None:
    """
    List Kubernetes secrets that use the specified certificate. :book:
    """

    if ctx.obj.debug:
        __debug_callback()

    cert = CertificateLoader(ctx.obj).load_certificate_file(cert_path=cert)
    output = (
        KubernetesSecretOperator(userdata=ctx.obj, cert=cert)
        .find_secrets()
        .get_secrets()
    )

    utils.console.print(
        (
            output
            if output
            else f"No secrets found that use the specified certificate \n{cert}"  # noqa
        ),
        style="bold green" if output else "bold red",
    )


@app.command(
    rich_help_panel="Commands",
    epilog="Made by \033[1;35mPiotr\033[0m :rocket: with passion \033[1;31m:heart:\033[0m",  # noqa
)
def patch(
    ctx: typer.Context,
    cert: Annotated[
        str,
        typer.Option(
            "-cert",
            "--cert",
            help="Path to the TLS certificate file",
            rich_help_panel="Arguments",
            show_default=False,
            callback=utils.validate_path,
        ),
    ],
    key: Annotated[
        str,
        typer.Option(
            "-key",
            "--key",
            help="Path to the TLS key file",
            rich_help_panel="Arguments",
            show_default=False,
            callback=utils.validate_path,
        ),
    ],
) -> None:
    """
    Patch Kubernetes secrets that use the specified certificate. :hammer:
    """

    if ctx.obj.debug:
        __debug_callback()

    # Load the certificate.
    certificate = CertificateLoader(ctx.obj).load_certificate_file(
        cert_path=cert, key_path=key
    )
    certificate.complement(cert=cert, key=key)

    utils.console.print(
        f"\nAre u sure to patch the secrets with the certificate: \n{certificate}",
        style="bold yellow",
    )
    if not typer.confirm("\nConfirm?"):
        utils.console.print("Operation aborted.", style="bold red")
        raise typer.Exit(code=1)

    # Patch secrets.
    output = (
        KubernetesSecretOperator(userdata=ctx.obj, cert=certificate)
        .find_secrets()
        .patch_secret()
    )

    utils.console.print(
        (output if output else "No secrets found to patch."),
        style="bold green" if output else "bold red",
    )


if __name__ == "__main__":
    app()
