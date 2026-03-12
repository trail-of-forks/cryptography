# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import binascii
import copy
import json
import os
import random

import pytest

from cryptography.exceptions import InvalidSignature, _Reasons
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.slhdsa import (
    SlhDsa256PrivateKey,
    SlhDsa256PublicKey,
)

try:
    from cryptography.hazmat.primitives.asymmetric.slhdsa import (
        SlhDsaParameterSet,
    )
except ImportError:
    pass

from ...doubles import DummyKeySerializationEncryption
from ...utils import load_vectors_from_file, raises_unsupported_algorithm


@pytest.mark.supported(
    only_if=lambda backend: not backend.slhdsa_supported(),
    skip_message="Requires backend without SLH-DSA support",
)
def test_slhdsa_unsupported(backend):
    # On non-BoringSSL backends, SlhDsaParameterSet doesn't exist,
    # but UnsupportedAlgorithm is raised before parameter_set is used.
    dummy_ps = None

    with raises_unsupported_algorithm(
        _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
    ):
        SlhDsa256PublicKey.from_public_bytes(
            dummy_ps,  # type: ignore[arg-type]
            b"0" * 64,
        )

    with raises_unsupported_algorithm(
        _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
    ):
        SlhDsa256PrivateKey.from_private_bytes(
            dummy_ps,  # type: ignore[arg-type]
            b"0" * 128,
        )

    with raises_unsupported_algorithm(
        _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
    ):
        SlhDsa256PrivateKey.generate(dummy_ps)  # type: ignore[arg-type]


@pytest.mark.supported(
    only_if=lambda backend: backend.slhdsa_supported(),
    skip_message="Requires backend with SLH-DSA support",
)
class TestSlhDsa256:
    def test_sign_verify_empty_message(self, backend):
        private_key = SlhDsa256PrivateKey.generate(
            SlhDsaParameterSet.SHAKE_256F
        )
        signature = private_key.sign(b"")
        private_key.public_key().verify(signature, b"")

    def test_sign_verify_context(self, backend):
        private_key = SlhDsa256PrivateKey.generate(
            SlhDsaParameterSet.SHAKE_256F
        )
        context = b"my context"
        signature = private_key.sign(b"test data", context=context)
        private_key.public_key().verify(
            signature, b"test data", context=context
        )

    def test_context_length_boundary(self, backend):
        private_key = SlhDsa256PrivateKey.generate(
            SlhDsaParameterSet.SHAKE_256F
        )
        msg = b"test data"

        # Valid: random length between 1 and 254
        valid_context = b"x" * random.randint(1, 254)
        signature = private_key.sign(msg, context=valid_context)
        private_key.public_key().verify(signature, msg, context=valid_context)

        # Valid: exactly 255 bytes (the maximum)
        limit_context = b"x" * 255
        signature = private_key.sign(msg, context=limit_context)
        private_key.public_key().verify(signature, msg, context=limit_context)

        # Invalid: random length between 256 and 500
        long_context = b"x" * random.randint(256, 500)
        with pytest.raises(ValueError):
            private_key.sign(msg, context=long_context)

        with pytest.raises(ValueError):
            private_key.public_key().verify(
                b"\x00" * 49856, msg, context=long_context
            )

    def test_from_private_bytes_wrong_length(self, backend):
        with pytest.raises(ValueError):
            SlhDsa256PrivateKey.from_private_bytes(
                SlhDsaParameterSet.SHAKE_256F, b"a" * 127
            )
        with pytest.raises(ValueError):
            SlhDsa256PrivateKey.from_private_bytes(
                SlhDsaParameterSet.SHAKE_256F, b"a" * 129
            )

    def test_from_public_bytes_wrong_length(self, backend):
        with pytest.raises(ValueError):
            SlhDsa256PublicKey.from_public_bytes(
                SlhDsaParameterSet.SHAKE_256F, b"a" * 63
            )
        with pytest.raises(ValueError):
            SlhDsa256PublicKey.from_public_bytes(
                SlhDsaParameterSet.SHAKE_256F, b"a" * 65
            )

    def test_private_bytes_raw_round_trip(self, backend):
        private_key = SlhDsa256PrivateKey.generate(
            SlhDsaParameterSet.SHAKE_256F
        )
        raw = private_key.private_bytes_raw()
        assert len(raw) == 128
        loaded = SlhDsa256PrivateKey.from_private_bytes(
            SlhDsaParameterSet.SHAKE_256F, raw
        )
        assert loaded.private_bytes_raw() == raw

    def test_public_bytes_raw_round_trip(self, backend):
        private_key = SlhDsa256PrivateKey.generate(
            SlhDsaParameterSet.SHAKE_256F
        )
        public_key = private_key.public_key()
        raw = public_key.public_bytes_raw()
        assert len(raw) == 64
        loaded = SlhDsa256PublicKey.from_public_bytes(
            SlhDsaParameterSet.SHAKE_256F, raw
        )
        assert loaded.public_bytes_raw() == raw

    def test_private_bytes_raw_format(self, backend):
        private_key = SlhDsa256PrivateKey.generate(
            SlhDsaParameterSet.SHAKE_256F
        )
        raw = private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        assert raw == private_key.private_bytes_raw()

    def test_public_bytes_raw_format(self, backend):
        private_key = SlhDsa256PrivateKey.generate(
            SlhDsaParameterSet.SHAKE_256F
        )
        public_key = private_key.public_key()
        raw = public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        assert raw == public_key.public_bytes_raw()

    def test_invalid_private_bytes(self, backend):
        private_key = SlhDsa256PrivateKey.generate(
            SlhDsaParameterSet.SHAKE_256F
        )
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
        public_key = SlhDsa256PrivateKey.generate(
            SlhDsaParameterSet.SHAKE_256F
        ).public_key()
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

    def test_parameter_set(self, backend):
        private_key = SlhDsa256PrivateKey.generate(
            SlhDsaParameterSet.SHAKE_256F
        )
        assert private_key.parameter_set == SlhDsaParameterSet.SHAKE_256F
        assert (
            private_key.public_key().parameter_set
            == SlhDsaParameterSet.SHAKE_256F
        )

    def test_invalid_parameter_set(self, backend):
        with pytest.raises(TypeError):
            SlhDsa256PrivateKey.generate("not-a-parameter-set")  # type: ignore[arg-type]

        with pytest.raises(TypeError):
            SlhDsa256PrivateKey.from_private_bytes(
                "not-a-parameter-set",  # type: ignore[arg-type]
                b"a" * 128,
            )

        with pytest.raises(TypeError):
            SlhDsa256PublicKey.from_public_bytes(
                "not-a-parameter-set",  # type: ignore[arg-type]
                b"a" * 64,
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

                    private_key = SlhDsa256PrivateKey.from_private_bytes(
                        SlhDsaParameterSet.SHAKE_256F, sk
                    )
                    assert private_key.private_bytes_raw() == sk
                    assert private_key.public_key().public_bytes_raw() == pk

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

                    public_key = SlhDsa256PublicKey.from_public_bytes(
                        SlhDsaParameterSet.SHAKE_256F, pk
                    )
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
    key1 = SlhDsa256PrivateKey.generate(SlhDsaParameterSet.SHAKE_256F)
    key2 = SlhDsa256PrivateKey.generate(SlhDsaParameterSet.SHAKE_256F)

    pub1a = key1.public_key()
    pub1b = SlhDsa256PublicKey.from_public_bytes(
        SlhDsaParameterSet.SHAKE_256F,
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
    key = SlhDsa256PrivateKey.generate(
        SlhDsaParameterSet.SHAKE_256F
    ).public_key()
    key2 = copy.copy(key)
    assert key == key2


@pytest.mark.supported(
    only_if=lambda backend: backend.slhdsa_supported(),
    skip_message="Requires backend with SLH-DSA support",
)
def test_public_key_deepcopy(backend):
    key = SlhDsa256PrivateKey.generate(
        SlhDsaParameterSet.SHAKE_256F
    ).public_key()
    key2 = copy.deepcopy(key)
    assert key == key2


@pytest.mark.supported(
    only_if=lambda backend: backend.slhdsa_supported(),
    skip_message="Requires backend with SLH-DSA support",
)
def test_private_key_copy(backend):
    key = SlhDsa256PrivateKey.generate(SlhDsaParameterSet.SHAKE_256F)
    key2 = copy.copy(key)
    assert key.private_bytes_raw() == key2.private_bytes_raw()


@pytest.mark.supported(
    only_if=lambda backend: backend.slhdsa_supported(),
    skip_message="Requires backend with SLH-DSA support",
)
def test_private_key_deepcopy(backend):
    key = SlhDsa256PrivateKey.generate(SlhDsaParameterSet.SHAKE_256F)
    key2 = copy.deepcopy(key)
    assert key.private_bytes_raw() == key2.private_bytes_raw()
