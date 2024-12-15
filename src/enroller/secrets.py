import base64

import enroller.data as data
import enroller.utils as utils
import kubernetes.client
import urllib3
from enroller.certs import CertificateLoader
from kubernetes import config
from kubernetes.client.rest import ApiException
from retry import retry


class KubernetesSecretOperator:
    """
    Class to manage Kubernetes secrets.
    """

    def __init__(self, cert: data.Certificate, userdata: data.UserData) -> None:
        self.cert = cert
        self.userdata = userdata

        self.kubernetes_certificates: list[data.Secrets] = []

        config.load_kube_config()
        self.api_client = kubernetes.client.ApiClient()
        self.v1 = kubernetes.client.CoreV1Api(self.api_client)

    def close(self) -> None:
        """
        Close the API client.
        """
        if self.api_client:
            self.api_client.close()

    @retry((ApiException, urllib3.exceptions.MaxRetryError), tries=3, delay=2)
    def find_secrets(self) -> list[data.Secrets]:
        """
        List Kubernetes secrets and find the ones that use the specified certificate.
        """

        try:
            secrets = self.v1.list_secret_for_all_namespaces(
                field_selector="type=kubernetes.io/tls"
            ).items

            kubernetes_certificate = CertificateLoader(userdata=self.userdata)
            self.kubernetes_certificates.clear()

            for secret in secrets:
                # Decode the certificate
                body = base64.b64decode(secret.data["tls.crt"])

                # Load the certificate
                certificate = kubernetes_certificate.load_certificate_string(
                    cert_data=body
                )

                # Compare the domains
                if set(self.cert.domains).intersection(certificate.domains):
                    self.kubernetes_certificates.append(
                        data.Secrets(
                            name=secret.metadata.name,
                            namespace=secret.metadata.namespace,
                            cert=certificate,
                        )
                    )
                    if self.userdata.verbose:
                        utils.console.print(
                            f"Secret: {secret.metadata.name} in namespace: {secret.metadata.namespace}",  # noqa
                            style="bold yellow",
                        )

        except ApiException as error:
            utils.console.print(f"Error listing secrets: {error}", style="bold red")

        except urllib3.exceptions.MaxRetryError as error:
            utils.console.print(f"MaxRetryError: {error}", style="bold red")

        finally:
            self.close()

        return self

    def get_secrets(self):
        return self.kubernetes_certificates

    @retry((ApiException, urllib3.exceptions.MaxRetryError), tries=3, delay=2)
    def patch_secret(self) -> None:
        """
        Patch the Kubernetes secret.
        """

        secret_data = {
            "data": {
                "tls.crt": self.cert.cert,
                "tls.key": self.cert.key,
            }
        }

        try:
            for secret in self.kubernetes_certificates:
                try:
                    self.v1.patch_namespaced_secret(
                        name=secret.name,
                        namespace=secret.namespace,
                        body=secret_data,
                        pretty="true",
                    )

                    if self.userdata.verbose:
                        utils.console.print(
                            f"Secret {secret.name} in namespace {secret.namespace} patched successfully.",  # noqa
                            style="bold yellow",
                        )

                except ApiException as error:
                    utils.console.print(
                        f"Error patching secret {secret.name} in namespace {secret.namespace}: {error}",  # noqa
                        style="bold red",
                    )

            # Prepare the output
            self.find_secrets()

        finally:
            self.close()

        return self.get_secrets()
