"""Low-level TUF Envelope API. (experimental!)

"""
import json
from typing import Generic, Type, cast

from securesystemslib.dsse import Envelope as BaseEnvelope

# Expose all payload classes via ``tuf.api.envelope`` as API alternative to
# ``tuf.api.metadata``.
from tuf.api._payload import (  # pylint: disable=unused-import
    _ROOT,
    _SNAPSHOT,
    _TARGETS,
    _TIMESTAMP,
    SPECIFICATION_VERSION,
    TOP_LEVEL_ROLE_NAMES,
    BaseFile,
    DelegatedRole,
    Delegations,
    MetaFile,
    Role,
    Root,
    Signed,
    Snapshot,
    SuccinctRoles,
    T,
    TargetFile,
    Targets,
    Timestamp,
)
from tuf.api.serialization import DeserializationError, SerializationError


class Envelope(Generic[T], BaseEnvelope):
    """Dead Simple Signing Envelope (DSSE) for TUF payloads.

    Signature creation and verification methods are provided by the base class
    implementation in ``securesystemslib``.

    """

    _DEFAULT_PAYLOAD_TYPE = "application/vnd.tuf+json"

    @classmethod
    def from_bytes(cls, data: bytes) -> "Envelope[T]":
        """Load TUF envelope from JSON bytes.

        NOTE: Unlike ``tuf.api.metadata.Metadata.from_bytes``, this method
        does not deserialize the contained payload. Use ``self.get_signed`` to
        deserialize the payload.

        Args:
            data: Envelope content.

        Raises:
            tuf.api.serialization.DeserializationError:
                The bytes cannot be deserialized.

        Returns:
            TUF ``Envelope`` object.
        """
        try:
            envelope_dict = json.loads(data.decode())
            envelope = Envelope.from_dict(envelope_dict)

        except Exception as e:
            raise DeserializationError from e

        return envelope

    def to_bytes(self) -> bytes:
        """Return Envelope object as JSON bytes.

        NOTE: Unlike ``tuf.api.metadata.Metadata.to_bytes``, this method does
        not serialize the payload. Use ``Envelope.from_signed`` to serialize a
        TUF Signed object and wrap it in an Envelope.

        Raises:
            tuf.api.serialization.SerializationError:
                The envelope object cannot be serialized.
        """
        try:
            envelope_dict = self.to_dict()
            json_bytes = json.dumps(envelope_dict).encode()

        except Exception as e:
            raise SerializationError from e

        return json_bytes

    @classmethod
    def from_signed(cls, signed: T) -> "Envelope[T]":
        """Serialize payload as JSON bytes and wrap in new Envelope.

        Args:
            signed: TUF payload.

        Raises:
            tuf.api.serialization.SerializationError:
                The signed object cannot be serialized.
        """
        try:
            signed_dict = signed.to_dict()
            json_bytes = json.dumps(signed_dict).encode()

        except Exception as e:
            raise SerializationError from e

        return cls(json_bytes, cls._DEFAULT_PAYLOAD_TYPE, [])

    def get_signed(self) -> T:
        """Unwrap TUF payload from Envelope and deserialize JSON bytes.

        Raises:
            tuf.api.serialization.SerializationError:
                The signed object cannot be deserialized.
        """

        try:
            payload_dict = json.loads(self.payload.decode())

            # TODO: can we move this to tuf.api._payload?
            _type = payload_dict["_type"]
            if _type == _TARGETS:
                inner_cls: Type[Signed] = Targets
            elif _type == _SNAPSHOT:
                inner_cls = Snapshot
            elif _type == _TIMESTAMP:
                inner_cls = Timestamp
            elif _type == _ROOT:
                inner_cls = Root
            else:
                raise ValueError(f'unrecognized metadata type "{_type}"')

        except Exception as e:
            raise DeserializationError from e

        return cast(T, inner_cls.from_dict(payload_dict))
