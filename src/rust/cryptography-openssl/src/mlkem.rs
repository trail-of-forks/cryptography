// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use foreign_types_shared::ForeignType;
use openssl_sys as ffi;
use std::os::raw::c_int;

use crate::{cvt, cvt_p, OpenSSLResult};

pub const NID_MLKEM768: c_int = ffi::NID_MLKEM768;
pub const PKEY_ID: openssl::pkey::Id = openssl::pkey::Id::from_raw(ffi::NID_kem);
pub const MLKEM768_PUBLIC_KEY_BYTES: usize = 1184;
pub const MLKEM768_SHARED_SECRET_BYTES: usize = 32;
pub const MLKEM768_SEED_BYTES: usize = 64;

extern "C" {
    fn EVP_PKEY_kem_new_raw_public_key(
        nid: c_int,
        in_: *const u8,
        len: usize,
    ) -> *mut ffi::EVP_PKEY;

    fn EVP_PKEY_CTX_kem_set_params(ctx: *mut ffi::EVP_PKEY_CTX, nid: c_int) -> c_int;

    fn EVP_PKEY_encapsulate(
        ctx: *mut ffi::EVP_PKEY_CTX,
        ciphertext: *mut u8,
        ciphertext_len: *mut usize,
        shared_secret: *mut u8,
        shared_secret_len: *mut usize,
    ) -> c_int;

    fn EVP_PKEY_decapsulate(
        ctx: *mut ffi::EVP_PKEY_CTX,
        shared_secret: *mut u8,
        shared_secret_len: *mut usize,
        ciphertext: *const u8,
        ciphertext_len: usize,
    ) -> c_int;

    fn EVP_PKEY_keygen_deterministic(
        ctx: *mut ffi::EVP_PKEY_CTX,
        out_pkey: *mut *mut ffi::EVP_PKEY,
        seed: *const u8,
        seed_len: *mut usize,
    ) -> c_int;
}

pub fn new_from_seed(seed: &[u8]) -> OpenSSLResult<openssl::pkey::PKey<openssl::pkey::Private>> {
    let ctx = openssl::pkey_ctx::PkeyCtx::new_id(PKEY_ID)?;
    // SAFETY: ctx is a valid EVP_PKEY_CTX for KEM.
    unsafe { cvt(EVP_PKEY_CTX_kem_set_params(ctx.as_ptr(), NID_MLKEM768))? };
    // SAFETY: ctx is a valid EVP_PKEY_CTX with KEM params set.
    unsafe { cvt(ffi::EVP_PKEY_keygen_init(ctx.as_ptr()))? };

    let mut pkey: *mut ffi::EVP_PKEY = std::ptr::null_mut();
    let mut seed_len = seed.len();
    // SAFETY: ctx is initialized for keygen, seed points to valid memory.
    unsafe {
        cvt(EVP_PKEY_keygen_deterministic(
            ctx.as_ptr(),
            &mut pkey,
            seed.as_ptr(),
            &mut seed_len,
        ))?;
        Ok(openssl::pkey::PKey::from_ptr(pkey))
    }
}

pub fn new_raw_public_key(
    data: &[u8],
) -> OpenSSLResult<openssl::pkey::PKey<openssl::pkey::Public>> {
    // SAFETY: data points to valid memory of the given length.
    unsafe {
        let pkey = cvt_p(EVP_PKEY_kem_new_raw_public_key(
            NID_MLKEM768,
            data.as_ptr(),
            data.len(),
        ))?;
        Ok(openssl::pkey::PKey::from_ptr(pkey))
    }
}

pub fn encapsulate(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> OpenSSLResult<(Vec<u8>, Vec<u8>)> {
    let ctx = openssl::pkey_ctx::PkeyCtx::new(pkey)?;

    let mut ct_len: usize = 0;
    let mut ss_len: usize = 0;
    // SAFETY: NULL output pointers to query required buffer sizes.
    unsafe {
        cvt(EVP_PKEY_encapsulate(
            ctx.as_ptr(),
            std::ptr::null_mut(),
            &mut ct_len,
            std::ptr::null_mut(),
            &mut ss_len,
        ))?;
    }

    let mut ciphertext = vec![0u8; ct_len];
    let mut shared_secret = vec![0u8; ss_len];
    // SAFETY: output buffers are allocated to the sizes returned above.
    unsafe {
        cvt(EVP_PKEY_encapsulate(
            ctx.as_ptr(),
            ciphertext.as_mut_ptr(),
            &mut ct_len,
            shared_secret.as_mut_ptr(),
            &mut ss_len,
        ))?;
    }
    ciphertext.truncate(ct_len);
    shared_secret.truncate(ss_len);
    Ok((ciphertext, shared_secret))
}

pub fn decapsulate(
    pkey: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
    ciphertext: &[u8],
) -> OpenSSLResult<Vec<u8>> {
    let ctx = openssl::pkey_ctx::PkeyCtx::new(pkey)?;

    let mut ss_len: usize = MLKEM768_SHARED_SECRET_BYTES;
    let mut shared_secret = vec![0u8; ss_len];
    // SAFETY: ctx is a valid EVP_PKEY_CTX, buffers are correctly sized.
    unsafe {
        cvt(EVP_PKEY_decapsulate(
            ctx.as_ptr(),
            shared_secret.as_mut_ptr(),
            &mut ss_len,
            ciphertext.as_ptr(),
            ciphertext.len(),
        ))?;
    }
    shared_secret.truncate(ss_len);
    Ok(shared_secret)
}
