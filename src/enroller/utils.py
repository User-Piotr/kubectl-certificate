import base64
import os

from rich.console import Console

console = Console()


def validate_path(path: str) -> str:
    """
    Validate the path.
    """
    if not path:
        console.print(
            "Error: No certificate path provided.",
            style="bold red",
        )
        raise RuntimeError

    if not os.path.isabs(path):
        path = os.path.join(os.getcwd(), path)

    if not os.path.exists(path):
        console.print(
            f"Error: The certificate file '{path}' does not exist.",
            style="bold red",
        )
        raise RuntimeError

    return path


def get_base64(path: str) -> str:
    """
    Read a file and return its content as a base64-encoded string.
    """
    try:
        with open(path, "rb") as raw_file:
            return base64.b64encode(raw_file.read()).decode("utf-8")
    except FileNotFoundError as error:
        raise FileNotFoundError(f"File not found: {error.filename}")
