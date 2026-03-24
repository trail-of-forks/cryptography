# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import copy

import pytest

from cryptography.exceptions import _Reasons
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MlKem768PrivateKey,
    MlKem768PublicKey,
)

from ...doubles import DummyKeySerializationEncryption
from ...utils import raises_unsupported_algorithm


@pytest.mark.supported(
    only_if=lambda backend: not backend.mlkem_supported(),
    skip_message="Requires a backend without ML-KEM-768 support",
)
def test_mlkem_unsupported(backend):
    with raises_unsupported_algorithm(
        _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
    ):
        MlKem768PrivateKey.from_seed_bytes(b"0" * 64)

    with raises_unsupported_algorithm(
        _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
    ):
        MlKem768PrivateKey.generate()

    with raises_unsupported_algorithm(
        _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
    ):
        MlKem768PublicKey.from_public_bytes(b"0" * 1184)


@pytest.mark.supported(
    only_if=lambda backend: backend.mlkem_supported(),
    skip_message="Requires a backend with ML-KEM-768 support",
)
class TestMlKem768:
    def test_encapsulate_decapsulate(self, backend):
        key = MlKem768PrivateKey.generate()
        pub = key.public_key()
        shared_secret, ciphertext = pub.encapsulate()
        decapped = key.decapsulate(ciphertext)
        assert shared_secret == decapped
        assert len(shared_secret) == 32
        assert len(ciphertext) == 1088

    def test_private_bytes_raw(self, backend):
        key = MlKem768PrivateKey.generate()
        raw = key.private_bytes_raw()
        assert len(raw) == 64
        assert raw == key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

    @pytest.mark.parametrize(
        ("encoding", "fmt", "encryption", "passwd", "load_func"),
        [
            (
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
                None,
                serialization.load_pem_private_key,
            ),
            (
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
                None,
                serialization.load_der_private_key,
            ),
            (
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(b"password"),
                b"password",
                serialization.load_pem_private_key,
            ),
            (
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(b"password"),
                b"password",
                serialization.load_der_private_key,
            ),
        ],
    )
    def test_round_trip_private_serialization(
        self, encoding, fmt, encryption, passwd, load_func, backend
    ):
        key = MlKem768PrivateKey.generate()
        serialized = key.private_bytes(encoding, fmt, encryption)
        loaded_key = load_func(serialized, passwd, backend)
        assert isinstance(loaded_key, MlKem768PrivateKey)
        # Verify round-trip by checking seed matches
        assert loaded_key.private_bytes_raw() == key.private_bytes_raw()

    @pytest.mark.parametrize(
        ("encoding", "fmt", "load_func"),
        [
            (
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
                serialization.load_pem_public_key,
            ),
            (
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
                serialization.load_der_public_key,
            ),
        ],
    )
    def test_round_trip_public_serialization(
        self, encoding, fmt, load_func, backend
    ):
        key = MlKem768PrivateKey.generate()
        pub = key.public_key()
        serialized = pub.public_bytes(encoding, fmt)
        loaded_pub = load_func(serialized, backend)
        assert isinstance(loaded_pub, MlKem768PublicKey)
        assert loaded_pub == pub

    def test_invalid_seed_length(self, backend):
        with pytest.raises(ValueError):
            MlKem768PrivateKey.from_seed_bytes(b"a" * 10)

    def test_invalid_type_seed(self, backend):
        with pytest.raises(TypeError):
            MlKem768PrivateKey.from_seed_bytes(
                object()  # type: ignore[arg-type]
            )

    def test_invalid_private_bytes(self, backend):
        key = MlKem768PrivateKey.generate()
        with pytest.raises(TypeError):
            key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                None,  # type: ignore[arg-type]
            )
        with pytest.raises(ValueError):
            key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                DummyKeySerializationEncryption(),
            )
        with pytest.raises(ValueError):
            key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.PKCS8,
                DummyKeySerializationEncryption(),
            )
        with pytest.raises(ValueError):
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )

    def test_invalid_public_bytes(self, backend):
        key = MlKem768PrivateKey.generate().public_key()
        with pytest.raises(ValueError):
            key.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        with pytest.raises(ValueError):
            key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.PKCS1,
            )
        with pytest.raises(ValueError):
            key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.Raw,
            )


@pytest.mark.supported(
    only_if=lambda backend: backend.mlkem_supported(),
    skip_message="Requires a backend with ML-KEM-768 support",
)
def test_public_key_equality(backend):
    key = MlKem768PrivateKey.generate()
    pub1 = key.public_key()
    pub2 = key.public_key()
    pub3 = MlKem768PrivateKey.generate().public_key()
    assert pub1 == pub2
    assert pub1 != pub3
    assert pub1 != object()

    with pytest.raises(TypeError):
        pub1 < pub2  # type: ignore[operator]


@pytest.mark.supported(
    only_if=lambda backend: backend.mlkem_supported(),
    skip_message="Requires a backend with ML-KEM-768 support",
)
def test_public_key_copy(backend):
    key = MlKem768PrivateKey.generate()
    pub1 = key.public_key()
    pub2 = copy.copy(pub1)
    assert pub1 == pub2


@pytest.mark.supported(
    only_if=lambda backend: backend.mlkem_supported(),
    skip_message="Requires a backend with ML-KEM-768 support",
)
def test_public_key_deepcopy(backend):
    key = MlKem768PrivateKey.generate()
    pub1 = key.public_key()
    pub2 = copy.deepcopy(pub1)
    assert pub1 == pub2


@pytest.mark.supported(
    only_if=lambda backend: backend.mlkem_supported(),
    skip_message="Requires a backend with ML-KEM-768 support",
)
def test_private_key_copy(backend):
    key1 = MlKem768PrivateKey.generate()
    key2 = copy.copy(key1)
    assert key1.private_bytes_raw() == key2.private_bytes_raw()


@pytest.mark.supported(
    only_if=lambda backend: backend.mlkem_supported(),
    skip_message="Requires a backend with ML-KEM-768 support",
)
def test_private_key_deepcopy(backend):
    key1 = MlKem768PrivateKey.generate()
    key2 = copy.deepcopy(key1)
    assert key1.private_bytes_raw() == key2.private_bytes_raw()
