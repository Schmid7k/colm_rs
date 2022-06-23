use super::arch::*;
use super::primitives::*;
use super::{DecryptionError, EncryptionError};
use aes::{Aes128Dec, Aes128Enc};
use cipher::inout::NotEqualError;
use cipher::{consts::U16, generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};

use core::simd::u8x16;

/// COLM authenticated encryption with associated data.
///
/// Representation of COLM0, no intermediate tag generation. (encryption-only)
pub struct Colm0Enc {
    aes: Aes128Enc,
}

impl Colm0Enc {
    pub fn new(key: &GenericArray<u8, U16>) -> Self {
        Self {
            aes: Aes128Enc::new(key),
        }
    }

    #[inline]
    fn aes_encrypt(&self, _in: __m128i) -> __m128i {
        let mut tmp = u8x16::from(byte_swap(_in));
        self.aes.encrypt_block(tmp.as_mut_array().into());
        byte_swap(tmp.into())
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
            v = self.aes_encrypt(v);

            while len >= 16 {
                delta = gf128_mul2(&delta);
                block = _mm_loadu_si128(ad[out.._in].as_ptr() as *const __m128i);
                block = byte_swap(block);
                block = _mm_xor_si128(block, delta);
                block = self.aes_encrypt(block);
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
                block = self.aes_encrypt(block);
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

            ll = self.aes_encrypt(ll);
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
                block = self.aes_encrypt(block);

                rho(&mut block, &mut w);

                block = self.aes_encrypt(block);
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
            block = self.aes_encrypt(block);

            rho(&mut block, &mut w);

            block = self.aes_encrypt(block);
            block = _mm_xor_si128(block, ldown);
            _mm_storeu_si128(c[out.._in].as_ptr() as *mut __m128i, byte_swap(block));
            out += 16;

            if remaining == 0 {
                return c;
            }

            lup = gf128_mul2(&lup);
            ldown = gf128_mul2(&ldown);

            block = _mm_xor_si128(checksum, lup);
            block = self.aes_encrypt(block);

            rho(&mut block, &mut w);

            block = self.aes_encrypt(block);
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

            ll = self.aes_encrypt(ll);
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
                block = self.aes_encrypt(block);

                rho(&mut block, &mut w);

                block = self.aes_encrypt(block);
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
            block = self.aes_encrypt(block);

            rho(&mut block, &mut w);

            block = self.aes_encrypt(block);
            block = _mm_xor_si128(block, ldown);
            _mm_storeu_si128(c[out.._in].as_ptr() as *mut __m128i, byte_swap(block));
            out += 16;

            if remaining == 0 {
                return Ok(c.len());
            }

            lup = gf128_mul2(&lup);
            ldown = gf128_mul2(&ldown);

            block = _mm_xor_si128(checksum, lup);
            block = self.aes_encrypt(block);

            rho(&mut block, &mut w);

            block = self.aes_encrypt(block);
            block = _mm_xor_si128(block, ldown);

            _mm_storeu_si128(buf.as_ptr() as *mut __m128i, byte_swap(block));
            c[out..].copy_from_slice(&buf[..remaining]);
            Ok(c.len())
        }
    }
}

/// COLM authenticated encryption with associated data.
///
/// Representation of COLM0, no intermediate tag generation. (decryption-only)
pub struct Colm0Dec {
    aes_dec: Aes128Dec,
    aes_enc: Aes128Enc,
}

impl Colm0Dec {
    pub fn new(key: &GenericArray<u8, U16>) -> Self {
        Self {
            aes_dec: Aes128Dec::new(key),
            aes_enc: Aes128Enc::new(key),
        }
    }

    #[inline]
    fn aes_encrypt(&self, _in: __m128i) -> __m128i {
        let mut tmp = u8x16::from(byte_swap(_in));
        self.aes_enc.encrypt_block(tmp.as_mut_array().into());
        byte_swap(tmp.into())
    }

    #[inline]
    fn aes_decrypt(&self, _in: __m128i) -> __m128i {
        let mut tmp = u8x16::from(byte_swap(_in));
        self.aes_dec.decrypt_block(tmp.as_mut_array().into());
        byte_swap(tmp.into())
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
            v = self.aes_encrypt(v);

            while len >= 16 {
                delta = gf128_mul2(&delta);
                block = _mm_loadu_si128(ad[out.._in].as_ptr() as *const __m128i);
                block = byte_swap(block);
                block = _mm_xor_si128(block, delta);
                block = self.aes_encrypt(block);
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
                block = self.aes_encrypt(block);
                v = _mm_xor_si128(v, block);
            }

            v
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

            ll = self.aes_encrypt(ll);
            lup = ll;
            ldown = gf128_mul3(&gf128_mul3(&ll));

            w = self.mac(ad, nonce, &ll);

            while remaining > 16 {
                lup = gf128_mul2(&lup);
                ldown = gf128_mul2(&ldown);

                inb = _mm_loadu_si128(c[out.._in].as_ptr() as *const __m128i);
                inb = byte_swap(inb);
                block = _mm_xor_si128(inb, ldown);
                block = self.aes_decrypt(block);

                rho_inv(&mut block, &mut w);

                block = self.aes_decrypt(block);
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
            block = self.aes_decrypt(block);

            rho_inv(&mut block, &mut w);

            block = self.aes_decrypt(block);
            block = _mm_xor_si128(block, lup);

            checksum = _mm_xor_si128(checksum, block);

            _mm_storeu_si128(buf.as_ptr() as *mut __m128i, byte_swap(checksum));
            m[out..].copy_from_slice(&buf[..remaining]);

            lup = gf128_mul2(&lup);
            ldown = gf128_mul2(&ldown);

            block = _mm_xor_si128(block, lup);
            block = self.aes_encrypt(block);

            rho(&mut block, &mut w);

            block = self.aes_encrypt(block);
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
    ) -> Result<usize, NotEqualError> {
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
                return Err(NotEqualError);
            }

            ll = self.aes_encrypt(ll);
            lup = ll;
            ldown = gf128_mul3(&gf128_mul3(&ll));

            w = self.mac(ad, nonce, &ll);

            while remaining > 16 {
                lup = gf128_mul2(&lup);
                ldown = gf128_mul2(&ldown);

                inb = _mm_loadu_si128(c[out.._in].as_ptr() as *const __m128i);
                inb = byte_swap(inb);
                block = _mm_xor_si128(inb, ldown);
                block = self.aes_decrypt(block);

                rho_inv(&mut block, &mut w);

                block = self.aes_decrypt(block);
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
            block = self.aes_decrypt(block);

            rho_inv(&mut block, &mut w);

            block = self.aes_decrypt(block);
            block = _mm_xor_si128(block, lup);

            checksum = _mm_xor_si128(checksum, block);

            _mm_storeu_si128(buf.as_ptr() as *mut __m128i, byte_swap(checksum));
            m[out..].copy_from_slice(&buf[..remaining]);

            lup = gf128_mul2(&lup);
            ldown = gf128_mul2(&ldown);

            block = _mm_xor_si128(block, lup);
            block = self.aes_encrypt(block);

            rho(&mut block, &mut w);

            block = self.aes_encrypt(block);
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