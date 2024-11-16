import os
from typing import Optional

import typer
from certificate.certs import CertificateInfo
from certificate.data import Parameters
from certificate.secrets import KubernetesSecrets
from certificate.version import __version__
from rich.console import Console
from typing_extensions import Annotated


console = Console()
app = typer.Typer(no_args_is_help=True, rich_markup_mode="markdown")


def __version_callback(value: bool):
    if value:
        console.print(f"CLI Version: {__version__}")
        raise typer.Exit()


def __validate_path(path: str) -> str:
    """
    Validate the path.
    """
    if not path:
        console.print(
            "Error: No certificate path provided.",
            style="bold red",
        )
        raise typer.Abort()

    if not os.path.isabs(path):
        path = os.path.join(os.getcwd(), path)

    if not os.path.exists(path):
        console.print(
            f"Error: The certificate file '{path}' does not exist.",
            style="bold red",
        )
        raise typer.Abort()

    return path


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
    **kubectl** enroll - A CLI tool to manage Kubernetes secrets,
      that use a specific certificate. :lock:

    * **List** - List the Kubernetes secrets that use the specified certificate.

    * **Patch** - Patch the Kubernetes secrets that use the specified certificate.

    ---

    """

    ctx.obj = Parameters(debug=debug, verbose=verbose)

    if debug:
        console.print("Debug mode enabled", style="bold yellow")
    if verbose:
        console.print("Verbose mode enabled", style="bold yellow")


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
        ),
    ],
    key: Annotated[
        Optional[str],
        typer.Option(
            "-key",
            "--key",
            help="Path to the TLS key file",
            rich_help_panel="Arguments",
            show_default=False,
        ),
    ] = None,
) -> None:
    """
    List the Kubernetes secrets that use the specified certificate. :book:
    """

    parameters = ctx.obj

    if parameters.debug:
        __debug_callback()

    parameters.cert_path = __validate_path(cert)
    parameters.cert = CertificateInfo.load_certificate_file(parameters)

    output = KubernetesSecrets(parameters).find_secrets().get_secrets()

    console.print(
        (
            output
            if output
            else f"No secrets found that use the specified certificate \n{parameters.cert}"  # noqa
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
        ),
    ],
) -> None:
    """
    Patch the Kubernetes secrets that use the specified certificate. :hammer:
    """

    parameters = ctx.obj

    if parameters.debug:
        __debug_callback()

    parameters.cert_path = __validate_path(cert)
    parameters.key_path = __validate_path(key)
    parameters.cert = CertificateInfo.load_certificate_file(parameters)

    KubernetesSecrets(parameters).find_secrets().patch_secret()


if __name__ == "__main__":
    app()
