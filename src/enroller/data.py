from dataclasses import dataclass
from dataclasses import field
from datetime import datetime

from enroller.utils import get_base64


@dataclass
class UserData:
    verbose: bool = False
    debug: bool = False


@dataclass
class Certificate:
    domains: list[str]
    expiration_date: datetime
    cert: str | None = field(default=None)
    key: str | None = field(default=None)

    def complement(self, cert: str, key: str) -> None:
        self.cert = get_base64(cert)
        self.key = get_base64(key)

    def __repr__(self):
        return f"Certificate(domains={self.domains}, expiration_date={self.expiration_date})"  # noqa


@dataclass
class Secrets:
    name: str
    namespace: str
    cert: Certificate
