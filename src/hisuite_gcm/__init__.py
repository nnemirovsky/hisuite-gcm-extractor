"""Tools for recovering recent Huawei HiSuite AES-GCM backups.

The package is layered so that presentation never sits in front of evidence:

``crypto``/``archive``/``manifest``
    Format-level primitives: authenticated decryption, safe TAR expansion,
    verifiable hashes.
``metadata``/``recovery``
    Read ``info.xml`` and apply each module's key only to that module's files.
``adapters``
    Optional, schema-specific readable exports, kept behind a plugin interface.
"""

from __future__ import annotations

from ._version import __version__
from .archive import ExtractionReport, extract_tar_safely, payload_kind
from .crypto import AuthenticationError, decrypt_file, derive_key_and_nonce, verify_file
from .manifest import ManifestResult, write_manifest
from .metadata import Module, find_backup, modules_from_info
from .recovery import Payload, RecoveryResult, discover, recover

__all__ = [
    "AuthenticationError",
    "ExtractionReport",
    "ManifestResult",
    "Module",
    "Payload",
    "RecoveryResult",
    "__version__",
    "decrypt_file",
    "derive_key_and_nonce",
    "discover",
    "extract_tar_safely",
    "find_backup",
    "modules_from_info",
    "payload_kind",
    "recover",
    "verify_file",
    "write_manifest",
]
