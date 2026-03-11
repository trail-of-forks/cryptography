# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import abc

from cryptography.exceptions import UnsupportedAlgorithm, _Reasons
from cryptography.hazmat.bindings._rust import openssl as rust_openssl
from cryptography.hazmat.primitives import _serialization
from cryptography.utils import Buffer

if hasattr(rust_openssl, "slhdsa"):
    SlhDsaParameterSet = rust_openssl.slhdsa.SlhDsaParameterSet


class SlhDsa256PublicKey(metaclass=abc.ABCMeta):
    @classmethod
    def from_public_bytes(
        cls,
        parameter_set: SlhDsaParameterSet,
        data: bytes,
    ) -> SlhDsa256PublicKey:
        from cryptography.hazmat.backends.openssl.backend import backend

        if not backend.slhdsa_supported():
            raise UnsupportedAlgorithm(
                "SLH-DSA is not supported by this version of the backend.",
                _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
            )

        return rust_openssl.slhdsa.from_public_bytes(parameter_set, data)

    @property
    @abc.abstractmethod
    def parameter_set(self) -> SlhDsaParameterSet:
        """
        The parameter set used by this key.
        """

    @abc.abstractmethod
    def verify(
        self,
        signature: Buffer,
        data: Buffer,
        context: Buffer | None = None,
    ) -> None:
        """
        Verify the signature.
        """

    @abc.abstractmethod
    def public_bytes_raw(self) -> bytes:
        """
        The raw bytes of the public key.
        """

    @abc.abstractmethod
    def public_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PublicFormat,
    ) -> bytes:
        """
        The serialized bytes of the public key.
        """

    @abc.abstractmethod
    def __eq__(self, other: object) -> bool:
        """
        Checks equality.
        """

    @abc.abstractmethod
    def __copy__(self) -> SlhDsa256PublicKey:
        """
        Returns a copy.
        """

    @abc.abstractmethod
    def __deepcopy__(self, memo: dict) -> SlhDsa256PublicKey:
        """
        Returns a deep copy.
        """


class SlhDsa256PrivateKey(metaclass=abc.ABCMeta):
    @classmethod
    def generate(
        cls, parameter_set: SlhDsaParameterSet
    ) -> SlhDsa256PrivateKey:
        from cryptography.hazmat.backends.openssl.backend import backend

        if not backend.slhdsa_supported():
            raise UnsupportedAlgorithm(
                "SLH-DSA is not supported by this version of the backend.",
                _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
            )

        return rust_openssl.slhdsa.generate_key(parameter_set)

    @classmethod
    def from_private_bytes(
        cls,
        parameter_set: SlhDsaParameterSet,
        data: Buffer,
    ) -> SlhDsa256PrivateKey:
        from cryptography.hazmat.backends.openssl.backend import backend

        if not backend.slhdsa_supported():
            raise UnsupportedAlgorithm(
                "SLH-DSA is not supported by this version of the backend.",
                _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM,
            )

        return rust_openssl.slhdsa.from_private_bytes(parameter_set, data)

    @property
    @abc.abstractmethod
    def parameter_set(self) -> SlhDsaParameterSet:
        """
        The parameter set used by this key.
        """

    @abc.abstractmethod
    def public_key(self) -> SlhDsa256PublicKey:
        """
        The SlhDsa256PublicKey derived from the private key.
        """

    @abc.abstractmethod
    def sign(
        self,
        data: Buffer,
        context: Buffer | None = None,
    ) -> bytes:
        """
        Signs the data.
        """

    @abc.abstractmethod
    def private_bytes_raw(self) -> bytes:
        """
        The raw bytes of the private key.
        """

    @abc.abstractmethod
    def private_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PrivateFormat,
        encryption_algorithm: _serialization.KeySerializationEncryption,
    ) -> bytes:
        """
        The serialized bytes of the private key.
        """

    @abc.abstractmethod
    def __copy__(self) -> SlhDsa256PrivateKey:
        """
        Returns a copy.
        """

    @abc.abstractmethod
    def __deepcopy__(self, memo: dict) -> SlhDsa256PrivateKey:
        """
        Returns a deep copy.
        """


if hasattr(rust_openssl, "slhdsa"):
    SlhDsa256PublicKey.register(rust_openssl.slhdsa.SlhDsa256PublicKey)
    SlhDsa256PrivateKey.register(rust_openssl.slhdsa.SlhDsa256PrivateKey)
