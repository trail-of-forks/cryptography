// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::OpenSSLResult;

pub const SHAKE_256F_PUBLIC_KEY_BYTES: usize = 64;
pub const SHAKE_256F_PRIVATE_KEY_BYTES: usize = 128;
pub const SHAKE_256F_SIGNATURE_BYTES: usize = 49856;

extern "C" {
    fn SLHDSA_SHAKE_256F_generate_key(out_public_key: *mut u8, out_private_key: *mut u8);

    fn SLHDSA_SHAKE_256F_public_from_private(out_public_key: *mut u8, private_key: *const u8);

    fn SLHDSA_SHAKE_256F_sign(
        out_signature: *mut u8,
        private_key: *const u8,
        msg: *const u8,
        msg_len: usize,
        context: *const u8,
        context_len: usize,
    ) -> std::os::raw::c_int;

    fn SLHDSA_SHAKE_256F_verify(
        signature: *const u8,
        signature_len: usize,
        public_key: *const u8,
        msg: *const u8,
        msg_len: usize,
        context: *const u8,
        context_len: usize,
    ) -> std::os::raw::c_int;
}

pub fn generate_key() -> (Vec<u8>, Vec<u8>) {
    let mut public_key = vec![0u8; SHAKE_256F_PUBLIC_KEY_BYTES];
    let mut private_key = vec![0u8; SHAKE_256F_PRIVATE_KEY_BYTES];

    // SAFETY: Buffers are correctly sized for the BoringSSL function.
    unsafe {
        SLHDSA_SHAKE_256F_generate_key(public_key.as_mut_ptr(), private_key.as_mut_ptr());
    }

    (public_key, private_key)
}

pub fn public_from_private(private_key: &[u8]) -> Vec<u8> {
    let mut public_key = vec![0u8; SHAKE_256F_PUBLIC_KEY_BYTES];

    // SAFETY: private_key is validated to be SHAKE_256F_PRIVATE_KEY_BYTES by the caller.
    // Output buffer is correctly sized.
    unsafe {
        SLHDSA_SHAKE_256F_public_from_private(public_key.as_mut_ptr(), private_key.as_ptr());
    }

    public_key
}

pub fn sign(private_key: &[u8], data: &[u8], context: &[u8]) -> OpenSSLResult<Vec<u8>> {
    let mut signature = vec![0u8; SHAKE_256F_SIGNATURE_BYTES];

    // SAFETY: All pointers and lengths are valid. private_key is validated by caller.
    let rc = unsafe {
        SLHDSA_SHAKE_256F_sign(
            signature.as_mut_ptr(),
            private_key.as_ptr(),
            data.as_ptr(),
            data.len(),
            context.as_ptr(),
            context.len(),
        )
    };

    crate::cvt(rc)?;
    Ok(signature)
}

pub fn verify(
    signature: &[u8],
    public_key: &[u8],
    data: &[u8],
    context: &[u8],
) -> OpenSSLResult<()> {
    // SAFETY: All pointers and lengths are valid. public_key is validated by caller.
    let rc = unsafe {
        SLHDSA_SHAKE_256F_verify(
            signature.as_ptr(),
            signature.len(),
            public_key.as_ptr(),
            data.as_ptr(),
            data.len(),
            context.as_ptr(),
            context.len(),
        )
    };

    crate::cvt(rc)?;
    Ok(())
}
