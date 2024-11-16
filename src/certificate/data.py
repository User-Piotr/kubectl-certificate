from dataclasses import dataclass
from dataclasses import field
from datetime import datetime
from typing import List

from typing_extensions import Optional


@dataclass
class Certificate:
    domains: List[str]
    expiration_date: datetime
    crt: Optional[str] = field(default=None)
    key: Optional[str] = field(default=None)

    def __repr__(self):
        return f"Certificate(domains={self.domains}, expiration_date={self.expiration_date})"  # noqa


@dataclass
class Secrets:
    name: str
    namespace: str
    certificate: Certificate


@dataclass
class Parameters:
    cert_path: str = None
    key_path: Optional[str] = None
    cert: Certificate = None
    debug: bool = False
    verbose: bool = False
