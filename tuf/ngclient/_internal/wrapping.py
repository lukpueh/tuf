# Copyright the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Extract and verify TUF payloads from different signature wrappers.

"""
import abc
from typing import Optional, Type, Union

from tuf.api import exceptions
from tuf.api.metadata import Metadata, Root, Signed, Targets

Delegator = Union[Root, Targets]


class Unwrapper(metaclass=abc.ABCMeta):
    """Interface for verifying TUF payload unwrappers."""

    @staticmethod
    def _validate_payload_type(signed: Signed, expected: Type[Signed]) -> None:
        if signed.type != expected.type:
            raise exceptions.RepositoryError(
                f"Expected '{expected.type}', got '{signed.type}'"
            )

    @abc.abstractmethod
    def unwrap(
        self,
        wrapper: bytes,
        delegator: Delegator,
        role_cls: Type[Signed],
        role_name: Optional[str] = None,
    ) -> Signed:
        """Unwrap, verify and return TUF payload (non-root).

        Use ``unwrap_root``for special verification.

        Arguments:
            wrapper: Raw signature wrapper bytes for role to verify.
            delegator: Delegator for the role to verify.
            role_cls: Class of the role to verify.
            role_name: Name of the role to verify. Defaults to
                `role_cls.type``, if not passed.

        Raises:
            tuf.exceptions.RepositoryError: Unexpected payload type

        Returns:
            Verified payload.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def unwrap_root(
        self, wrapper: bytes, delegator: Optional[Root] = None
    ) -> Root:
        """Unwrap, verify and return TUF payload of type root.

        NOTE: ``unwrap_root`` differs from other ``wrap``, as it
        - may skip delegator verification for root v1
        - includes self-verification

        wrapper: Raw signature wrapper bytes for role to verify.
        delegator: Previous root to verify payload. If not passed, delegator
                verification is skipped.

        Raises:
            tuf.exceptions.RepositoryError: Unexpected payload type

        Returns:
            Verified payload.
        """

        raise NotImplementedError


class MetadataUnwrapper(Unwrapper):
    """Unwrapper implementation for Metadata payloads."""

    def unwrap(
        self,
        wrapper: bytes,
        delegator: Delegator,
        role_cls: Type[Signed],
        role_name: Optional[str] = None,
    ) -> Signed:  # noqa: D102
        if role_name is None:
            role_name = role_cls.type

        md = Metadata.from_bytes(wrapper)
        self._validate_payload_type(md.signed, role_cls)

        delegator.verify_delegate(role_name, md.signed_bytes, md.signatures)

        return md.signed

    def unwrap_root(
        self, wrapper: bytes, delegator: Optional[Root] = None
    ) -> Root:  # noqa: D102
        md = Metadata[Root].from_bytes(wrapper)
        self._validate_payload_type(md.signed, Root)

        if delegator:
            delegator.verify_delegate(Root.type, md.signed_bytes, md.signatures)

        md.signed.verify_delegate(Root.type, md.signed_bytes, md.signatures)

        return md.signed
