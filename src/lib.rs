#![feature(portable_simd)]

pub mod colm0;
mod primitives;

#[cfg(target_arch = "x86")]
use core::arch::x86 as arch;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64 as arch;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("The provided ciphertext buffer was too small.")]
    ShortCiphertext,
}

#[derive(Debug, Error)]
pub enum DecryptionError {
    #[error("Ciphertext did not include a complete tag.")]
    MissingTag,
    #[error("Tag verification failed")]
    InvalidTag,
    #[error("The provided plaintext buffer was too small.")]
    ShortPlaintext,
}
