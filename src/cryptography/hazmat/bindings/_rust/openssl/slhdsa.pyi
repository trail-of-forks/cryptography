# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from cryptography.hazmat.primitives.asymmetric import slhdsa
from cryptography.utils import Buffer

class SlhDsaParameterSet:
    SHAKE_256F: SlhDsaParameterSet

class SlhDsa256PrivateKey: ...
class SlhDsa256PublicKey: ...

def generate_key(
    parameter_set: slhdsa.SlhDsaParameterSet,
) -> slhdsa.SlhDsa256PrivateKey: ...
def from_private_bytes(
    parameter_set: slhdsa.SlhDsaParameterSet,
    data: Buffer,
) -> slhdsa.SlhDsa256PrivateKey: ...
def from_public_bytes(
    parameter_set: slhdsa.SlhDsaParameterSet,
    data: bytes,
) -> slhdsa.SlhDsa256PublicKey: ...
