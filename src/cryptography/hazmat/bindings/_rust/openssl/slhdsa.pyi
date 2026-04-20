# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from cryptography.hazmat.primitives.asymmetric import slhdsa
from cryptography.utils import Buffer

class SlhDsaShake256fPrivateKey: ...
class SlhDsaShake256fPublicKey: ...

def generate_key() -> slhdsa.SlhDsaShake256fPrivateKey: ...
def from_private_bytes(
    data: Buffer,
) -> slhdsa.SlhDsaShake256fPrivateKey: ...
def from_public_bytes(
    data: bytes,
) -> slhdsa.SlhDsaShake256fPublicKey: ...
