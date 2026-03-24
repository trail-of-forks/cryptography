# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import binascii

import pytest

from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MlKem768PrivateKey,
    MlKem768PublicKey,
)

from .utils import wycheproof_tests


@pytest.mark.supported(
    only_if=lambda backend: backend.mlkem_supported(),
    skip_message="Requires a backend with ML-KEM-768 support",
)
@wycheproof_tests("mlkem_768_test.json")
def test_mlkem768_decaps(backend, wycheproof):
    seed = binascii.unhexlify(wycheproof.testcase["seed"])
    try:
        key = MlKem768PrivateKey.from_seed_bytes(seed)
    except ValueError:
        assert wycheproof.invalid
        return

    ct = binascii.unhexlify(wycheproof.testcase["c"])
    expected_ss = binascii.unhexlify(wycheproof.testcase["K"])

    try:
        shared_secret = key.decapsulate(ct)
    except Exception as e:
        print(e, f"{wycheproof.invalid=}")
    if wycheproof.valid:
        assert shared_secret == expected_ss
    else:
        assert shared_secret != expected_ss


@pytest.mark.supported(
    only_if=lambda backend: backend.mlkem_supported(),
    skip_message="Requires a backend with ML-KEM-768 support",
)
@wycheproof_tests("mlkem_768_keygen_seed_test.json")
def test_mlkem768_keygen_seed(backend, wycheproof):
    seed = binascii.unhexlify(wycheproof.testcase["seed"])
    expected_ek = binascii.unhexlify(wycheproof.testcase["ek"])

    key = MlKem768PrivateKey.from_seed_bytes(seed)

    pub = key.public_key()
    assert pub.public_bytes_raw() == expected_ek


@pytest.mark.supported(
    only_if=lambda backend: backend.mlkem_supported(),
    skip_message="Requires a backend with ML-KEM-768 support",
)
@wycheproof_tests("mlkem_768_encaps_test.json")
def test_mlkem768_encaps_invalid_ek(backend, wycheproof):
    if not wycheproof.valid:
        # We can't reproduce the encapsulation without seedable RNG
        return

    ek = binascii.unhexlify(wycheproof.testcase["ek"])
    with pytest.raises(ValueError):
        MlKem768PublicKey.from_public_bytes(ek)
