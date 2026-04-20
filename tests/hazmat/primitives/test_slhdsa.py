# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import binascii
import copy
import json
import os

import pytest

from cryptography.exceptions import InvalidSignature, _Reasons
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.slhdsa import (
    SlhDsaShake256fPrivateKey,
    SlhDsaShake256fPublicKey,
)

from ...doubles import DummyKeySerializationEncryption
from ...utils import load_vectors_from_file, raises_unsupported_algorithm


@pytest.mark.supported(
    only_if=lambda backend: not backend.slhdsa_supported(),
    skip_message="Requires backend without SLH-DSA support",
)
def test_slhdsa_unsupported(backend):
    with raises_unsupported_algorithm(
        _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
    ):
        SlhDsaShake256fPublicKey.from_public_bytes(
            b"0" * 64,
        )

    with raises_unsupported_algorithm(
        _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
    ):
        SlhDsaShake256fPrivateKey.from_private_bytes(
            b"0" * 128,
        )

    with raises_unsupported_algorithm(
        _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
    ):
        SlhDsaShake256fPrivateKey.generate()


@pytest.mark.supported(
    only_if=lambda backend: backend.slhdsa_supported(),
    skip_message="Requires backend with SLH-DSA support",
)
class TestSlhDsaShake256f:
    def test_sign_verify(self, backend):
        key = SlhDsaShake256fPrivateKey.generate()
        sig = key.sign(b"test data")
        key.public_key().verify(sig, b"test data")

    @pytest.mark.parametrize(
        "ctx",
        [
            b"ctx",
            b"a" * 255,
        ],
    )
    def test_sign_verify_with_context(self, backend, ctx):
        key = SlhDsaShake256fPrivateKey.generate()
        sig = key.sign(b"test data", ctx)
        key.public_key().verify(sig, b"test data", ctx)

    def test_context_too_long(self, backend):
        key = SlhDsaShake256fPrivateKey.generate()
        with pytest.raises(ValueError):
            key.sign(b"data", b"x" * 256)
        with pytest.raises(ValueError):
            key.public_key().verify(b"sig", b"data", b"x" * 256)

    def test_from_private_bytes_wrong_length(self, backend):
        with pytest.raises(ValueError):
            SlhDsaShake256fPrivateKey.from_private_bytes(b"a" * 127)
        with pytest.raises(ValueError):
            SlhDsaShake256fPrivateKey.from_private_bytes(b"a" * 129)

    def test_from_public_bytes_wrong_length(self, backend):
        with pytest.raises(ValueError):
            SlhDsaShake256fPublicKey.from_public_bytes(b"a" * 63)
        with pytest.raises(ValueError):
            SlhDsaShake256fPublicKey.from_public_bytes(b"a" * 65)

    def test_private_bytes_raw_round_trip(self, backend):
        private_key = SlhDsaShake256fPrivateKey.generate()
        raw = private_key.private_bytes_raw()
        assert len(raw) == 128
        loaded = SlhDsaShake256fPrivateKey.from_private_bytes(raw)
        assert loaded.private_bytes_raw() == raw

    def test_public_bytes_raw_round_trip(self, backend):
        private_key = SlhDsaShake256fPrivateKey.generate()
        public_key = private_key.public_key()
        raw = public_key.public_bytes_raw()
        assert len(raw) == 64
        loaded = SlhDsaShake256fPublicKey.from_public_bytes(raw)
        assert loaded.public_bytes_raw() == raw

    def test_private_bytes_raw_format(self, backend):
        private_key = SlhDsaShake256fPrivateKey.generate()
        raw = private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        assert raw == private_key.private_bytes_raw()

    def test_public_bytes_raw_format(self, backend):
        private_key = SlhDsaShake256fPrivateKey.generate()
        public_key = private_key.public_key()
        raw = public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        assert raw == public_key.public_bytes_raw()

    def test_invalid_private_bytes(self, backend):
        private_key = SlhDsaShake256fPrivateKey.generate()
        with pytest.raises(TypeError):
            private_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                None,  # type: ignore[arg-type]
            )
        with pytest.raises(ValueError):
            private_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                DummyKeySerializationEncryption(),
            )
        with pytest.raises(ValueError):
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
        with pytest.raises(ValueError):
            private_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )

    def test_invalid_public_bytes(self, backend):
        public_key = SlhDsaShake256fPrivateKey.generate().public_key()
        with pytest.raises(ValueError):
            public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.Raw,
            )
        with pytest.raises(ValueError):
            public_key.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )

    def test_keygen_vectors(self, backend, subtests):
        vectors = load_vectors_from_file(
            os.path.join("asymmetric", "SLHDSA", "keygen.json"),
            lambda f: json.load(f),
        )
        for group in vectors["testGroups"]:
            if group["parameterSet"] != "SLH-DSA-SHAKE-256f":
                continue
            for test in group["tests"]:
                with subtests.test():
                    sk = binascii.unhexlify(test["sk"])
                    pk = binascii.unhexlify(test["pk"])

                    private_key = SlhDsaShake256fPrivateKey.from_private_bytes(
                        sk
                    )
                    assert private_key.private_bytes_raw() == sk
                    assert private_key.public_key().public_bytes_raw() == pk

    def test_siggen_vectors(self, backend, subtests):
        vectors = load_vectors_from_file(
            os.path.join("asymmetric", "SLHDSA", "siggen.json"),
            lambda f: json.load(f),
        )
        for group in vectors["testGroups"]:
            if group["parameterSet"] != "SLH-DSA-SHAKE-256f":
                continue
            for test in group["tests"]:
                with subtests.test():
                    sk = binascii.unhexlify(test["sk"])
                    pk = binascii.unhexlify(test["pk"])
                    msg = binascii.unhexlify(test["message"])
                    ctx = binascii.unhexlify(test["context"])
                    sig = binascii.unhexlify(test["signature"])

                    private_key = SlhDsaShake256fPrivateKey.from_private_bytes(
                        sk
                    )
                    assert private_key.public_key().public_bytes_raw() == pk

                    pub = SlhDsaShake256fPublicKey.from_public_bytes(pk)
                    pub.verify(sig, msg, ctx if ctx else None)

    def test_sigver_vectors(self, backend, subtests):
        vectors = load_vectors_from_file(
            os.path.join("asymmetric", "SLHDSA", "sigver.json"),
            lambda f: json.load(f),
        )
        for group in vectors["testGroups"]:
            if group["parameterSet"] != "SLH-DSA-SHAKE-256f":
                continue
            for test in group["tests"]:
                with subtests.test():
                    pk = binascii.unhexlify(test["pk"])
                    msg = binascii.unhexlify(test["message"])
                    sig = binascii.unhexlify(test["signature"])
                    ctx = binascii.unhexlify(test["context"])

                    public_key = SlhDsaShake256fPublicKey.from_public_bytes(pk)
                    context = ctx if ctx else None

                    if test["testPassed"]:
                        public_key.verify(sig, msg, context=context)
                    else:
                        with pytest.raises(InvalidSignature):
                            public_key.verify(sig, msg, context=context)


@pytest.mark.supported(
    only_if=lambda backend: backend.slhdsa_supported(),
    skip_message="Requires backend with SLH-DSA support",
)
def test_public_key_equality(backend):
    key1 = SlhDsaShake256fPrivateKey.generate()
    key2 = SlhDsaShake256fPrivateKey.generate()

    pub1a = key1.public_key()
    pub1b = SlhDsaShake256fPublicKey.from_public_bytes(
        key1.public_key().public_bytes_raw(),
    )
    pub2 = key2.public_key()

    assert pub1a == pub1b
    assert pub1a != pub2
    assert pub1a != object()

    with pytest.raises(TypeError):
        pub1a < pub1b  # type: ignore[operator]


@pytest.mark.supported(
    only_if=lambda backend: backend.slhdsa_supported(),
    skip_message="Requires backend with SLH-DSA support",
)
def test_public_key_copy(backend):
    key = SlhDsaShake256fPrivateKey.generate().public_key()
    key2 = copy.copy(key)
    assert key == key2


@pytest.mark.supported(
    only_if=lambda backend: backend.slhdsa_supported(),
    skip_message="Requires backend with SLH-DSA support",
)
def test_public_key_deepcopy(backend):
    key = SlhDsaShake256fPrivateKey.generate().public_key()
    key2 = copy.deepcopy(key)
    assert key == key2


@pytest.mark.supported(
    only_if=lambda backend: backend.slhdsa_supported(),
    skip_message="Requires backend with SLH-DSA support",
)
def test_private_key_copy(backend):
    key = SlhDsaShake256fPrivateKey.generate()
    key2 = copy.copy(key)
    assert key.private_bytes_raw() == key2.private_bytes_raw()


@pytest.mark.supported(
    only_if=lambda backend: backend.slhdsa_supported(),
    skip_message="Requires backend with SLH-DSA support",
)
def test_private_key_deepcopy(backend):
    key = SlhDsaShake256fPrivateKey.generate()
    key2 = copy.deepcopy(key)
    assert key.private_bytes_raw() == key2.private_bytes_raw()
