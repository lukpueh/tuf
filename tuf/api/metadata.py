"""TUF role metadata model.

This module provides container classes for TUF role metadata, including methods
to read/serialize/write from and to JSON, perform TUF-compliant metadata
updates, and create and verify signatures.

"""
# Imports.

# 1st-party.
# from tuf.api.keys import KeyRing

# 2nd-party.
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import json
import tempfile

# 3rd-party.

from securesystemslib.formats import encode_canonical
from securesystemslib.util import load_json_file, persist_temp_file
from securesystemslib.storage import StorageBackendInterface
from tuf.repository_lib import (
    _get_written_metadata,
    _strip_version_number,
    generate_snapshot_metadata,
    generate_targets_metadata,
    generate_timestamp_metadata,
)

import iso8601
import tuf.formats

# Types.

JsonDict = Dict[str, Any]

# Classes.


class Metadata(ABC):
    # FIXME: Can't add type hint signed: Signed, because Signed is defined
    # below. But can't move Metadata under Signed, because Signed.read_json_metadata
    # has Metadata type hint. :/
    def __init__(self, signed, signatures) -> None:
        self.signed = signed
        self.signatures = signatures


    # # And you would use this method to populate it from a file.
    # @classmethod
    # def read_from_json(cls, filename: str, storage_backend: Optional[StorageBackendInterface] = None) -> Metadata:
    #     signable = load_json_file(filename, storage_backend)
    #     tuf.formats.SIGNABLE_SCHEMA.check_match(signable)

    #     signatures = signable['signatures']
    #     signed = signable['signed']

    #     # We always intend times to be UTC
    #     # NOTE: we could do this with datetime.fromisoformat() but that is not
    #     # available in Python 2.7's datetime
    #     expiration = iso8601.parse_date(signed['expires']).replace(tzinfo=None)
    #     version = signed['version']

    #     fn, fn_ver = _strip_version_number(filename, True)
    #     if fn_ver:
    #         assert fn_ver == self.__version, f'{fn_ver} != {self.__version}'
    #         consistent_snapshot = True
    #     else:
    #         consistent_snapshot = False

    #     metadata = cls(consistent_snapshot=consistent_snapshot,
    #                    expiration=expiration,
    #                    version=version)

    #     metadata._signatures = signatures
    #     metadata._signed = signed

    #     return metadata


    # @property
    # def expiration(self) -> datetime:
    #     return self.__expiration

    # @expiration.setter
    # def expiration(self, datetime) -> None:
    #     # We always treat dates as UTC
    #     self.__expiration = datetime.replace(tzinfo=None)

    # def bump_version(self) -> None:
    #     self.__version = self.__version + 1

    # def bump_expiration(self, delta: timedelta = timedelta(days=1)) -> None:
    #     self.__expiration = self.__expiration + delta

    # def __update_signature(self, signatures, keyid, signature):
    #     updated = False
    #     keyid_signature = {'keyid':keyid, 'sig':signature}
    #     for idx, keyid_sig in enumerate(signatures):
    #         if keyid_sig['keyid'] == keyid:
    #             signatures[idx] = keyid_signature
    #             updated = True
    #     if not updated:
    #         signatures.append(keyid_signature)

    # def sign(self) -> JsonDict:
    #     signed_bytes = self.signed_bytes
    #     signatures = self.__signatures

    #     for key in self.__keyring.keys:
    #         signature = key.sign(signed_bytes)
    #         self.__update_signature(signatures, key.keyid, signature)

    #     self.__signatures = signatures
    #     return self.signable

    # def verify(self) -> bool:
    #     signed_bytes = self.signed_bytes
    #     signatures = self.signatures
    #     verified_keyids = {}

    #     for signature in signatures:
    #         # TODO: handle an empty keyring
    #         for key in self.__keyring.keys:
    #             keyid = key.keyid
    #             if keyid == signature['keyid']:
    #                 try:
    #                     verified = key.verify(signed_bytes, signature)
    #                 except:
    #                     logging.exception(f'Could not verify signature for key {keyid}')
    #                     continue
    #                 else:
    #                     # Avoid https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-6174
    #                     verified_keyids |= keyid
    #                     break

    #     return len(verified_keyids) >= self.__keyring.threshold.least

    # def write_to_json(self, filename: str, storage_backend: StorageBackendInterface = None) -> None:
    #      with tempfile.TemporaryFile() as f:
    #         f.write(_get_written_metadata(self.sign()).encode_canonical())
    #         persist_temp_file(f, filename, storage_backend)


class Signed:
    # TODO: Re-think we default values. It might be better to pass some things
    # as args and not es kwargs. Then we'd need to pop those from
    # signable["signed"] in read_json_metadata and pass them explicitly.
    def __init__(self, _type: str = None, expires: datetime = datetime.today(), version: int = 0, spec_version: str = None) -> None:
        self._type = _type
        self.spec_version = spec_version

        # We always intend times to be UTC
        # NOTE: we could do this with datetime.fromisoformat() but that is not
        # available in Python 2.7's datetime
        # NOTE: Store as datetime object for convenient handling, use 'expires'
        # property to get the TUF metadata format representation
        self.__expiration = iso8601.parse_date(expires).replace(tzinfo=None)

        if version < 0:
            raise ValueError(f'version must be < 0, got {version}')
        self.version = version


    @property
    def expires(self) -> str:
        """The expiration property in TUF metadata format."""
        return self.__expiration.isoformat()+'Z'


    @property
    def signed_bytes(self) -> bytes:
        return encode_canonical(self.as_dict()).encode('UTF-8')


    @classmethod
    def read_json_metadata(cls, filename: str, storage_backend: Optional[StorageBackendInterface] = None) -> Metadata:
        signable = load_json_file(filename, storage_backend)
        tuf.formats.SIGNABLE_SCHEMA.check_match(signable)

        # TODO: It feels a bit dirty to access signable["signed"]["version"]
        # here in order to do this check, and also a bit random (there are
        # likely other things to check), but later we don't have the filename
        # anymore. If we want to stick to the check, which seems reasonable, we
        # should maybe think of a better place.
        _, fn_prefix = _strip_version_number(filename, True)
        if fn_prefix and fn_prefix != signable["signed"]["version"]:
            raise ValueError(
                    f'version filename prefix ({fn_prefix}) must align with '
                    f'version in metadata ({signable["signed"]["version"]}).')

        return Metadata(
                signed=cls(**signable["signed"]),
                signatures=signable["signatures"])


class Timestamp(Signed):
    def __init__(self, _type: str = None, expires: datetime = datetime.today(), version: int = 0, spec_version: str = None, meta: JsonDict = None) -> None:
        super().__init__(_type, expires, version, spec_version)
        self.meta = meta


    def as_dict(self) -> JsonDict:
        return tuf.formats.build_dict_conforming_to_schema(
            tuf.formats.TIMESTAMP_SCHEMA, version=self.__version,
            expires=self.expires, meta=self.snapshot_fileinfo)

    # Update metadata about the snapshot metadata.
    def update(self, version: int, length: int, hashes: JsonDict) -> None:
        fileinfo = self.meta.get('snapshot.json', {})
        fileinfo['version'] = version
        fileinfo['length'] = length
        fileinfo['hashes'] = hashes
        self.meta['snapshot.json'] = fileinfo





# class Snapshot(Signed):
#     def __init__(self, consistent_snapshot: bool = True, expiration: datetime = datetime.today(), keyring: KeyRing = None, version: int = 1) -> None:
#         super().__init__(consistent_snapshot, expiration, keyring, version)
#         self.targets_fileinfo = {}

#     @classmethod
#     def read_from_json(cls, filename: str) -> Metadata:
#         md = Metadata.read_from_json(filename)
#         snapshot = cls(md.consistent_snapshot, md.expiration, md.keyring, md.version)
#         meta = md._signed['meta']
#         for target_role in meta:
#             version = meta[target_role]['version']
#             length = meta[target_role].get('length')
#             hashes = meta[target_role].get('hashes')
#             snapshot.targets_fileinfo[target_role] = tuf.formats.make_metadata_fileinfo(version, length, hashes)
#         tuf.formats.SNAPSHOT_SCHEMA.check_match(snapshot.signed)
#         snapshot._signatures = md._signatures
#         return snapshot

#     def as_dict(self) -> JsonDict:
#         return tuf.formats.build_dict_conforming_to_schema(
#             tuf.formats.SNAPSHOT_SCHEMA, version=self.__version,
#             expires=self.expires, meta=self.targets_fileinfo)

#     # Add or update metadata about the targets metadata.
#     def update(self, rolename: str, version: int, length: Optional[int] = None, hashes: Optional[JsonDict] = None) -> None:
#         self.targets_fileinfo[f'{rolename}.json'] = tuf.formats.make_metadata_fileinfo(version, length, hashes)


# class Targets(Signed):
#     def __init__(self, consistent_snapshot: bool = True, expiration: datetime = datetime.today(), keyring: KeyRing = None, version: int = 1) -> None:
#         super().__init__(consistent_snapshot, expiration, keyring, version)
#         self.targets = {}
#         self.delegations = {}

#     @classmethod
#     def read_from_json(cls, filename: str) -> Metadata:
#         targets = Metadata.read_from_json(filename)
#         targets.targets = self.__signed['targets']
#         targets.delegations = self.__signed.get('delegations', {})
#         tuf.formats.TARGETS_SCHEMA.check_match(targets.signed)
#         targets._signatures = md._signatures
#         return targets

#     def as_dict(self) -> JsonDict:
#         return tuf.formats.build_dict_conforming_to_schema(
#             tuf.formats.TARGETS_SCHEMA,
#             version=self.__version,
#             expires=self.expires,
#             targets=self.targets,
#             delegations=self.delegations)

#     # Add or update metadata about the target.
#     def update(self, filename: str, fileinfo: JsonDict) -> None:
#         self.targets[filename] = fileinfo
