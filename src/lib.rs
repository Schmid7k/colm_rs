use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128Dec, Aes128Enc};
use cipher::{consts::U16, generic_array::GenericArray};

use core::arch::x86_64::{
    __m128i, _mm_and_si128, _mm_loadu_si128, _mm_or_si128, _mm_set_epi64x, _mm_set_epi8,
    _mm_setzero_si128, _mm_shuffle_epi32, _mm_shuffle_epi8, _mm_slli_epi64, _mm_slli_si128,
    _mm_srai_epi32, _mm_srli_epi64, _mm_storeu_si128, _mm_xor_si128,
};
use std::mem;

#[inline]
unsafe fn aes_encrypt(_in: __m128i, cipher: &Aes128Enc) -> __m128i {
    let tmp = byte_swap(_in);
    cipher.encrypt_block(mem::transmute(&tmp as *const __m128i));
    byte_swap(tmp)
}

#[inline]
unsafe fn aes_decrypt(_in: __m128i, cipher: &Aes128Dec) -> __m128i {
    let tmp = byte_swap(_in);
    cipher.decrypt_block(mem::transmute(&tmp as *const __m128i));
    byte_swap(tmp)
}

#[inline]
unsafe fn byte_swap(x: __m128i) -> __m128i {
    let bswap_mask = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    _mm_shuffle_epi8(x, bswap_mask)
}

#[inline]
unsafe fn gf128_mul2(x: &__m128i) -> __m128i {
    let redpoly = _mm_set_epi64x(0, 0x87); // Set our irreducible polynomial by which to reduce polynomial multiplication over GF(2)

    let mut mask = _mm_srai_epi32(*x, 31); // Set mask for branchless conditional
    mask = _mm_shuffle_epi32(mask, 0xff);

    /*
    let mut mask = _mm_cmpgt_epi32(zero, x); // Set mask
    mask = _mm_shuffle_epi32(mask, 0xff);
    */

    let x2 = _mm_or_si128(
        // Bitwise OR between
        _mm_slli_epi64(*x, 1), // x shifted left by 1 (equals multiplication by 2)
        _mm_srli_epi64(_mm_slli_si128::<8>(*x), 63), // and x shifted left by 8 and shifted right by 63.
    );

    _mm_xor_si128(x2, _mm_and_si128(redpoly, mask)) // Return bitwise XOR of x2 with the bitwise AND between the irreducible polynomial and mask
}

#[inline]
unsafe fn gf128_mul3(x: &__m128i) -> __m128i {
    _mm_xor_si128(gf128_mul2(x), *x)
}

#[inline]
unsafe fn gf128_mul7(x: &__m128i) -> __m128i {
    let x2 = gf128_mul2(x);
    let x4 = gf128_mul2(&x2);

    _mm_xor_si128(x4, _mm_xor_si128(x2, *x))
}

#[inline]
unsafe fn rho(block: &mut __m128i, w: &mut __m128i) {
    let new_w = _mm_xor_si128(gf128_mul2(w), *block);
    *block = _mm_xor_si128(new_w, *w);
    *w = new_w;
}

#[inline]
unsafe fn rho_inv(block: &mut __m128i, w: &mut __m128i) {
    let new_w = gf128_mul2(w);
    *w = _mm_xor_si128(*w, *block);
    *block = _mm_xor_si128(new_w, *w);
}

#[inline]
unsafe fn mac(ad: &[u8], nonce: &[u8; 8], ll: &__m128i, cipher: &Aes128Enc) -> __m128i {
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
    v = aes_encrypt(v, cipher);

    while len >= 16 {
        delta = gf128_mul2(&delta);
        block = _mm_loadu_si128(ad[out.._in].as_ptr() as *const __m128i);
        block = byte_swap(block);
        block = _mm_xor_si128(block, delta);
        block = aes_encrypt(block, cipher);
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
        block = aes_encrypt(block, cipher);
        v = _mm_xor_si128(v, block);
    }

    v
}

pub unsafe fn crypto_aead_encrypt(
    c: &mut [u8],
    m: &[u8],
    ad: &[u8],
    nonce: &[u8; 8],
    key: &GenericArray<u8, U16>,
) {
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
    let cipher = Aes128Enc::new(key);

    let mut out = 0;
    let mut _in = 16;
    let mut remaining = m.len();

    ll = aes_encrypt(ll, &cipher);
    lup = ll;
    ldown = gf128_mul3(&gf128_mul3(&ll));

    w = mac(ad, nonce, &ll, &cipher);

    while remaining > 16 {
        lup = gf128_mul2(&lup);
        ldown = gf128_mul2(&ldown);

        inb = _mm_loadu_si128(m[out.._in].as_ptr() as *const __m128i);
        inb = byte_swap(inb);
        checksum = _mm_xor_si128(checksum, inb);
        block = _mm_xor_si128(inb, lup);
        block = aes_encrypt(block, &cipher);

        rho(&mut block, &mut w);

        block = aes_encrypt(block, &cipher);
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
    block = aes_encrypt(block, &cipher);

    rho(&mut block, &mut w);

    block = aes_encrypt(block, &cipher);
    block = _mm_xor_si128(block, ldown);
    _mm_storeu_si128(c[out.._in].as_ptr() as *mut __m128i, byte_swap(block));
    out += 16;

    if remaining == 0 {
        return;
    }

    lup = gf128_mul2(&lup);
    ldown = gf128_mul2(&ldown);

    block = _mm_xor_si128(checksum, lup);
    block = aes_encrypt(block, &cipher);

    rho(&mut block, &mut w);

    block = aes_encrypt(block, &cipher);
    block = _mm_xor_si128(block, ldown);

    _mm_storeu_si128(buf.as_ptr() as *mut __m128i, byte_swap(block));
    c[out..].copy_from_slice(&buf[..remaining]);
}

pub unsafe fn crypto_aead_decrypt(
    m: &mut [u8],
    c: &[u8],
    ad: &[u8],
    nonce: &[u8; 8],
    key: &GenericArray<u8, U16>,
) {
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

    let enc_cipher = Aes128Enc::new(key);
    let dec_cipher = Aes128Dec::new(key);

    let mut _in = 16;
    let mut out = 0;
    let mut remaining = c.len() - 16;

    if c.len() < 16 {
        return;
    }

    ll = aes_encrypt(ll, &enc_cipher);
    lup = ll;
    ldown = gf128_mul3(&gf128_mul3(&ll));

    w = mac(ad, nonce, &ll, &enc_cipher);

    while remaining > 16 {
        lup = gf128_mul2(&lup);
        ldown = gf128_mul2(&ldown);

        inb = _mm_loadu_si128(c[out.._in].as_ptr() as *const __m128i);
        inb = byte_swap(inb);
        block = _mm_xor_si128(inb, ldown);
        block = aes_decrypt(block, &dec_cipher);

        rho_inv(&mut block, &mut w);

        block = aes_decrypt(block, &dec_cipher);
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
    block = aes_decrypt(block, &dec_cipher);

    rho_inv(&mut block, &mut w);

    block = aes_decrypt(block, &dec_cipher);
    block = _mm_xor_si128(block, lup);

    checksum = _mm_xor_si128(checksum, block);

    _mm_storeu_si128(buf.as_ptr() as *mut __m128i, byte_swap(checksum));
    m[out..].copy_from_slice(&buf[..remaining]);

    lup = gf128_mul2(&lup);
    ldown = gf128_mul2(&ldown);

    block = _mm_xor_si128(block, lup);
    block = aes_encrypt(block, &enc_cipher);

    rho(&mut block, &mut w);

    block = aes_encrypt(block, &enc_cipher);
    block = _mm_xor_si128(block, ldown);

    _mm_storeu_si128(buf.as_ptr() as *mut __m128i, byte_swap(block));

    if remaining < 16 {
        _mm_storeu_si128(buf.as_ptr() as *mut __m128i, byte_swap(checksum));
        assert!(buf[remaining] == 0x80);
        for i in buf.iter().skip(remaining + 1) {
            assert!(*i == 0);
        }
    }
}
