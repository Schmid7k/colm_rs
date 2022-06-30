//! The [COLM][1] [Authenticated Encryption and Associated Data (AEAD)][2] cipher.
//! 
//! COLM has been selected as the second choice for the defense-in-depth
//! scenario during the [CAESAR competition][3].
//! 
//! ## Security Notes
//! 
//! This crate has *NOT* received any security audit BUT was verified informally
//! by an author of the official COLM document.
//! 
//! It has been paid close attention to provide constant-time operations though
//! it was not yet formally verified, whether this holds true.
//! 
//! **USE AT YOUR OWN RISK.**
//! 
//! # Usage
//! ```
//! use colm::colm0::Colm0;
//! use aes::{Aes128Enc, Aes128Dec}; // Can be any BlockCipher implementing `BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt/BlockDecrypt + KeyInit + KeySizeUser<KeySize = U16>`
//! 
//! let key = b"just another key";
//! let cipher = Colm0::<Aes128Enc, Aes128Dec>::new(key.into());
//! let nonce = b"a nonce!";
//! let ad = b"";
//! let ciphertext = cipher.seal(b"plaintext message", ad, nonce);
//! 
//! let plaintext = cipher.open(&ciphertext, ad, nonce).expect("decryption failure!"); // NOTE: handle this error to avoid panics!
//! 
//! assert_eq!(&plaintext, b"plaintext message");
//! ```
//! 
//! ## From-To Usage
//! 
//! COLM can also encrypt/decrypt a message/ciphertext into a separate, already existing ciphertext buffer.
//! 
//! It is important to note, that the destination buffer needs to be 16 bytes **larger** than the original message,
//! because it has to fit the tag!
//! ```
//! use colm::colm0::Colm0;
//! use aes::{Aes128Enc, Aes128Dec}; // Can be any BlockCipher implementing `BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt/BlockDecrypt + KeyInit + KeySizeUser<KeySize = U16>`
//! 
//! let key = b"just another key";
//! let cipher = Colm0::<Aes128Enc, Aes128Dec>::new(key.into());
//! let nonce = b"a nonce!";
//! let ad = b"";
//! let mut plaintext_buffer = [0u8; 16]; // 16 byte plaintext message
//! let mut ciphertext_buffer = [0u8; 32]; // length of plaintext + 16 byte destination buffer
//! 
//! let cipher_bytes = cipher.seal_into(&mut ciphertext_buffer, b"example message!", ad, nonce).expect("encryption error!"); // Encrypt plaintext content and place output in `ciphertext_buffer`, then return amount of bytes written.
//! 
//! let plain_bytes = cipher.open_into(&mut plaintext_buffer, &ciphertext_buffer, ad, nonce).expect("decryption error!"); // Decrypt ciphertext_buffer content and place output back in plaintext, then return amount of bytes written.
//! 
//! assert_eq!(b"example message!", &plaintext_buffer);
//! ```
//!
//! [1]: https://competitions.cr.yp.to/round2/colm.pdf
//! [2]: https://en.wikipedia.org/wiki/Authenticated_encryption
//! [3]: https://competitions.cr.yp.to/caesar-submissions.html

use super::arch::*;
use super::primitives::*;
use super::{DecryptionError, EncryptionError};
use aead::{NewAead, AeadCore, AeadInPlace, Error};
use cipher::{Key, KeyInit, KeySizeUser, BlockCipher, BlockSizeUser, BlockEncrypt, BlockDecrypt, consts::{U16, U8}, generic_array::GenericArray};

use core::simd::u8x16;

#[cfg(feature = "aes")]
pub use aes;

#[cfg(feature = "aes")]
use aes::{Aes128Enc, Aes128Dec, Aes128};


/// COLM nonces
pub type Nonce = GenericArray<u8, U8>;

pub type Tag = GenericArray<u8, U16>;



/// COLM authenticated encryption with associated data.
///
/// Representation of COLM0, no intermediate tag generation.
pub struct Colm0<E, D> {
    enc: BcEnc<E>,
    dec: BcDec<D>,
}

impl<E, D> Colm0<E, D>
where
    E: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt + KeyInit + KeySizeUser<KeySize = U16>,
    D: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockDecrypt + KeyInit + KeySizeUser<KeySize = U16>,
{
    pub fn new(key: &GenericArray<u8, U16>) -> Self {
        Self { enc: BcEnc::new(key), dec: BcDec::new(key) }
    }

    #[inline]
    fn mac(&self, ad: &[u8], nonce: &[u8; 8], ll: &__m128i) -> __m128i {
        unsafe {
            let mut v: __m128i;
            let mut delta: __m128i;
            let mut block: __m128i;
            let mut buf = [0u8; 16];
            let mut len = ad.len();
            let mut _in = 16;
            let mut out = 0;

            delta = gf128_mul3(ll);
            v = _mm_set_epi64x(0, i64::from_be_bytes(*nonce));
            v = byte_swap(v);
            v = _mm_xor_si128(v, delta);
            v = self.enc.bc_encrypt(v);

            while len >= 16 {
                delta = gf128_mul2(&delta);
                block = _mm_loadu_si128(ad[out.._in].as_ptr() as *const __m128i);
                block = byte_swap(block);
                block = _mm_xor_si128(block, delta);
                block = self.enc.bc_encrypt(block);
                v = _mm_xor_si128(v, block);

                len -= 16;
                _in += 16;
                out += 16;
            }

            if len > 0 {
                delta = gf128_mul7(&delta);
                buf[0..len].copy_from_slice(&ad[out..out + len]);
                buf[len] ^= 0x80;
                block = _mm_loadu_si128(buf[0..16].as_ptr() as *const __m128i);
                block = byte_swap(block);
                block = _mm_xor_si128(block, delta);
                block = self.enc.bc_encrypt(block);
                v = _mm_xor_si128(v, block);
            }

            v
        }
    }

    pub fn seal(&self, m: &[u8], ad: &[u8], nonce: &[u8; 8]) -> Vec<u8> {
        unsafe {
            let mut buf = [0u8; 16];

            let (mut w, mut block, mut lup, mut ldown, mut inb): (
                __m128i,
                __m128i,
                __m128i,
                __m128i,
                __m128i,
            );
            let mut checksum = _mm_setzero_si128();
            let mut ll = _mm_setzero_si128();

            let mut out = 0;
            let mut _in = 16;
            let mut remaining = m.len();

            let mut c = vec![0u8; remaining + 16];

            ll = self.enc.bc_encrypt(ll);
            lup = ll;
            ldown = gf128_mul3(&gf128_mul3(&ll));

            w = self.mac(ad, nonce, &ll);

            while remaining > 16 {
                lup = gf128_mul2(&lup);
                ldown = gf128_mul2(&ldown);

                inb = _mm_loadu_si128(m[out.._in].as_ptr() as *const __m128i);
                inb = byte_swap(inb);
                checksum = _mm_xor_si128(checksum, inb);
                block = _mm_xor_si128(inb, lup);
                block = self.enc.bc_encrypt(block);

                rho(&mut block, &mut w);

                block = self.enc.bc_encrypt(block);
                block = _mm_xor_si128(block, ldown);
                _mm_storeu_si128(c[out.._in].as_ptr() as *mut __m128i, byte_swap(block));

                out += 16;
                _in += 16;
                remaining -= 16;
            }

            buf[..remaining].copy_from_slice(&m[out..]);

            lup = gf128_mul7(&lup);
            ldown = gf128_mul7(&ldown);
            if remaining < 16 {
                buf[remaining] = 0x80;
                lup = gf128_mul7(&lup);
                ldown = gf128_mul7(&ldown);
            }
            inb = _mm_loadu_si128(buf.as_ptr() as *const __m128i);
            inb = byte_swap(inb);
            checksum = _mm_xor_si128(checksum, inb);

            block = _mm_xor_si128(checksum, lup);
            block = self.enc.bc_encrypt(block);

            rho(&mut block, &mut w);

            block = self.enc.bc_encrypt(block);
            block = _mm_xor_si128(block, ldown);
            _mm_storeu_si128(c[out.._in].as_ptr() as *mut __m128i, byte_swap(block));
            out += 16;

            if remaining == 0 {
                return c;
            }

            lup = gf128_mul2(&lup);
            ldown = gf128_mul2(&ldown);

            block = _mm_xor_si128(checksum, lup);
            block = self.enc.bc_encrypt(block);

            rho(&mut block, &mut w);

            block = self.enc.bc_encrypt(block);
            block = _mm_xor_si128(block, ldown);

            _mm_storeu_si128(buf.as_ptr() as *mut __m128i, byte_swap(block));
            c[out..].copy_from_slice(&buf[..remaining]);
            c
        }
    }

    pub fn seal_into(
        &self,
        c: &mut [u8],
        m: &[u8],
        ad: &[u8],
        nonce: &[u8; 8],
    ) -> Result<usize, EncryptionError> {
        unsafe {
            if c.len() - m.len() < 16 {
                return Err(EncryptionError::ShortCiphertext);
            }
            let mut buf = [0u8; 16];

            let (mut w, mut block, mut lup, mut ldown, mut inb): (
                __m128i,
                __m128i,
                __m128i,
                __m128i,
                __m128i,
            );
            let mut checksum = _mm_setzero_si128();
            let mut ll = _mm_setzero_si128();

            let mut out = 0;
            let mut _in = 16;
            let mut remaining = m.len();

            ll = self.enc.bc_encrypt(ll);
            lup = ll;
            ldown = gf128_mul3(&gf128_mul3(&ll));

            w = self.mac(ad, nonce, &ll);

            while remaining > 16 {
                lup = gf128_mul2(&lup);
                ldown = gf128_mul2(&ldown);

                inb = _mm_loadu_si128(m[out.._in].as_ptr() as *const __m128i);
                inb = byte_swap(inb);
                checksum = _mm_xor_si128(checksum, inb);
                block = _mm_xor_si128(inb, lup);
                block = self.enc.bc_encrypt(block);

                rho(&mut block, &mut w);

                block = self.enc.bc_encrypt(block);
                block = _mm_xor_si128(block, ldown);
                _mm_storeu_si128(c[out.._in].as_ptr() as *mut __m128i, byte_swap(block));

                out += 16;
                _in += 16;
                remaining -= 16;
            }

            buf[..remaining].copy_from_slice(&m[out..]);

            lup = gf128_mul7(&lup);
            ldown = gf128_mul7(&ldown);
            if remaining < 16 {
                buf[remaining] = 0x80;
                lup = gf128_mul7(&lup);
                ldown = gf128_mul7(&ldown);
            }
            inb = _mm_loadu_si128(buf.as_ptr() as *const __m128i);
            inb = byte_swap(inb);
            checksum = _mm_xor_si128(checksum, inb);

            block = _mm_xor_si128(checksum, lup);
            block = self.enc.bc_encrypt(block);

            rho(&mut block, &mut w);

            block = self.enc.bc_encrypt(block);
            block = _mm_xor_si128(block, ldown);
            _mm_storeu_si128(c[out.._in].as_ptr() as *mut __m128i, byte_swap(block));
            out += 16;

            if remaining == 0 {
                return Ok(c.len());
            }

            lup = gf128_mul2(&lup);
            ldown = gf128_mul2(&ldown);

            block = _mm_xor_si128(checksum, lup);
            block = self.enc.bc_encrypt(block);

            rho(&mut block, &mut w);

            block = self.enc.bc_encrypt(block);
            block = _mm_xor_si128(block, ldown);

            _mm_storeu_si128(buf.as_ptr() as *mut __m128i, byte_swap(block));
            c[out..].copy_from_slice(&buf[..remaining]);
            Ok(c.len())
        }
    }

    pub fn open(&self, c: &[u8], ad: &[u8], nonce: &[u8; 8]) -> Result<Vec<u8>, DecryptionError> {
        unsafe {
            let buf = [0u8; 16];
            let (mut w, mut block, mut lup, mut ldown, mut inb): (
                __m128i,
                __m128i,
                __m128i,
                __m128i,
                __m128i,
            );
            let mut checksum = _mm_setzero_si128();
            let mut ll = _mm_setzero_si128();

            let mut _in = 16;
            let mut out = 0;
            let mut remaining = c.len() - 16;

            if c.len() < 16 {
                return Err(DecryptionError::MissingTag);
            }

            let mut m = vec![0u8; remaining];

            ll = self.enc.bc_encrypt(ll);
            lup = ll;
            ldown = gf128_mul3(&gf128_mul3(&ll));

            w = self.mac(ad, nonce, &ll);

            while remaining > 16 {
                lup = gf128_mul2(&lup);
                ldown = gf128_mul2(&ldown);

                inb = _mm_loadu_si128(c[out.._in].as_ptr() as *const __m128i);
                inb = byte_swap(inb);
                block = _mm_xor_si128(inb, ldown);
                block = self.dec.bc_decrypt(block);

                rho_inv(&mut block, &mut w);

                block = self.dec.bc_decrypt(block);
                block = _mm_xor_si128(block, lup);
                checksum = _mm_xor_si128(checksum, block);

                _mm_storeu_si128(m[out.._in].as_ptr() as *mut __m128i, byte_swap(block));

                out += 16;
                _in += 16;
                remaining -= 16;
            }

            lup = gf128_mul7(&lup);
            ldown = gf128_mul7(&ldown);
            if remaining < 16 {
                lup = gf128_mul7(&lup);
                ldown = gf128_mul7(&ldown);
            }

            inb = _mm_loadu_si128(c[out.._in].as_ptr() as *const __m128i);
            inb = byte_swap(inb);
            block = _mm_xor_si128(inb, ldown);
            block = self.dec.bc_decrypt(block);

            rho_inv(&mut block, &mut w);

            block = self.dec.bc_decrypt(block);
            block = _mm_xor_si128(block, lup);

            checksum = _mm_xor_si128(checksum, block);

            _mm_storeu_si128(buf.as_ptr() as *mut __m128i, byte_swap(checksum));
            m[out..].copy_from_slice(&buf[..remaining]);

            lup = gf128_mul2(&lup);
            ldown = gf128_mul2(&ldown);

            block = _mm_xor_si128(block, lup);
            block = self.enc.bc_encrypt(block);

            rho(&mut block, &mut w);

            block = self.enc.bc_encrypt(block);
            block = _mm_xor_si128(block, ldown);

            _mm_storeu_si128(buf.as_ptr() as *mut __m128i, byte_swap(block));

            if remaining < 16 {
                _mm_storeu_si128(buf.as_ptr() as *mut __m128i, byte_swap(checksum));
                assert!(buf[remaining] == 0x80);
                for i in buf.iter().skip(remaining + 1) {
                    assert!(*i == 0);
                }
            }
            Ok(m)
        }
    }

    pub fn open_into(
        &self,
        m: &mut [u8],
        c: &[u8],
        ad: &[u8],
        nonce: &[u8; 8],
    ) -> Result<usize, DecryptionError> {
        if c.len() < 16 {
            return Err(DecryptionError::MissingTag);
        }
        
        unsafe {
            let buf = [0u8; 16];
            let (mut w, mut block, mut lup, mut ldown, mut inb): (
                __m128i,
                __m128i,
                __m128i,
                __m128i,
                __m128i,
            );
            let mut checksum = _mm_setzero_si128();
            let mut ll = _mm_setzero_si128();

            let mut _in = 16;
            let mut out = 0;
            let mut remaining = c.len() - 16;

            ll = self.enc.bc_encrypt(ll);
            lup = ll;
            ldown = gf128_mul3(&gf128_mul3(&ll));

            w = self.mac(ad, nonce, &ll);

            while remaining > 16 {
                lup = gf128_mul2(&lup);
                ldown = gf128_mul2(&ldown);

                inb = _mm_loadu_si128(c[out.._in].as_ptr() as *const __m128i);
                inb = byte_swap(inb);
                block = _mm_xor_si128(inb, ldown);
                block = self.dec.bc_decrypt(block);

                rho_inv(&mut block, &mut w);

                block = self.dec.bc_decrypt(block);
                block = _mm_xor_si128(block, lup);
                checksum = _mm_xor_si128(checksum, block);

                _mm_storeu_si128(m[out.._in].as_ptr() as *mut __m128i, byte_swap(block));

                out += 16;
                _in += 16;
                remaining -= 16;
            }

            lup = gf128_mul7(&lup);
            ldown = gf128_mul7(&ldown);
            if remaining < 16 {
                lup = gf128_mul7(&lup);
                ldown = gf128_mul7(&ldown);
            }

            inb = _mm_loadu_si128(c[out.._in].as_ptr() as *const __m128i);
            inb = byte_swap(inb);
            block = _mm_xor_si128(inb, ldown);
            block = self.dec.bc_decrypt(block);

            rho_inv(&mut block, &mut w);

            block = self.dec.bc_decrypt(block);
            block = _mm_xor_si128(block, lup);

            checksum = _mm_xor_si128(checksum, block);

            _mm_storeu_si128(buf.as_ptr() as *mut __m128i, byte_swap(checksum));
            m[out..].copy_from_slice(&buf[..remaining]);

            lup = gf128_mul2(&lup);
            ldown = gf128_mul2(&ldown);

            block = _mm_xor_si128(block, lup);
            block = self.enc.bc_encrypt(block);

            rho(&mut block, &mut w);

            block = self.enc.bc_encrypt(block);
            block = _mm_xor_si128(block, ldown);

            _mm_storeu_si128(buf.as_ptr() as *mut __m128i, byte_swap(block));

            if remaining < 16 {
                _mm_storeu_si128(buf.as_ptr() as *mut __m128i, byte_swap(checksum));
                assert!(buf[remaining] == 0x80);
                for i in buf.iter().skip(remaining + 1) {
                    assert!(*i == 0);
                }
            }
            Ok(m.len())
        }
    }
}

struct BcEnc<E>
{
    enc: E,
}

impl<E> KeySizeUser for BcEnc<E>
where
    E: KeyInit,
{
    type KeySize = E::KeySize;
}

impl<E> NewAead for BcEnc<E>
where
    E: BlockSizeUser<BlockSize = U16> + BlockEncrypt + KeyInit,
{
    type KeySize = E::KeySize;

    fn new(key: &Key<Self>) -> Self {
        E::new(key).into()
    }
}

impl<E> From<E> for BcEnc<E>
where
    E: BlockSizeUser<BlockSize = U16> + BlockEncrypt,
{
    fn from(cipher: E) -> Self {
        Self { enc: cipher }
    }
}

impl<E> BcEnc<E>
    where E: KeyInit + BlockSizeUser<BlockSize = U16> + BlockEncrypt,
{
    #[inline]
    fn bc_encrypt(&self, _in: __m128i) -> __m128i {
        let mut tmp = u8x16::from(byte_swap(_in));
        self.enc.encrypt_block(tmp.as_mut_array().into());
        byte_swap(tmp.into())
    }
}

struct BcDec<D>
{
    dec: D,
}

impl<D> KeySizeUser for BcDec<D>
where
    D: KeyInit,
{
    type KeySize = D::KeySize;
}

impl<D> NewAead for BcDec<D>
where
    D: BlockSizeUser<BlockSize = U16> + BlockDecrypt + KeyInit,
{
    type KeySize = D::KeySize;

    fn new(key: &Key<Self>) -> Self {
        D::new(key).into()
    }
}

impl<D> From<D> for BcDec<D>
where
    D: BlockSizeUser<BlockSize = U16> + BlockDecrypt,
{
    fn from(cipher: D) -> Self {
        Self { dec: cipher }
    }
}

impl<D> BcDec<D>
    where D: KeyInit + BlockSizeUser<BlockSize = U16> + BlockDecrypt,
{
    #[inline]
    fn bc_decrypt(&self, _in: __m128i) -> __m128i {
        let mut tmp = u8x16::from(byte_swap(_in));
        self.dec.decrypt_block(tmp.as_mut_array().into());
        byte_swap(tmp.into())
    }
}