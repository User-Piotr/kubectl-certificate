import base64

from certificate.data import Certificate
from certificate.data import Parameters
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from rich.console import Console

console = Console()


class CertificateInfo:

    def __extractr_cert_details(cert, verbose: bool) -> Certificate:
        """
        Extract the certificate details.
        """

        # Get the domain names.
        try:
            san_extension = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            domain_names = san_extension.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            domain_names = []

        # Get the expiration date
        expiration_date = cert.not_valid_after_utc

        if verbose:
            console.print("Subject Details:", style="bold")
            for domain in domain_names:
                console.print(f"  - {domain}")

            console.print(
                f"Expiration Date: {expiration_date.strftime('%Y-%m-%d %H:%M:%S')}"
            )

        return Certificate(domains=domain_names, expiration_date=expiration_date)

    @staticmethod
    def load_certificate_file(parameters: Parameters) -> Certificate:
        """
        Load a certificate from a file.
        """

        # Load the certificate.
        with open(parameters.cert_path, "rb") as cert_file:
            cert_data = cert_file.read()
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())

        return CertificateInfo.__extractr_cert_details(cert, parameters.verbose)

    @staticmethod
    def load_certificate_string(cert_data, parameters: Parameters) -> Certificate:
        """
        Load a certificate from a PEM-encoded string.
        """

        cert = x509.load_pem_x509_certificate(cert_data, default_backend())

        return CertificateInfo.__extractr_cert_details(cert, parameters.verbose)

    @staticmethod
    def get_base64(path: str) -> base64:
        """
        Read a file and return its content as a base64-encoded string.
        """
        try:
            with open(path, "rb") as raw_file:
                return base64.b64encode(raw_file.read()).decode("utf-8")
        except FileNotFoundError as error:
            raise FileNotFoundError(f"File not found: {error.filename}")
