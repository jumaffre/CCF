/* Copyright (c) INRIA and Microsoft Corporation. All rights reserved.
   Licensed under the Apache 2.0 License. */

/* This file was generated by KreMLin <https://github.com/FStarLang/kremlin>
 * then hand-edited to use MSVC intrinsics KreMLin invocation:
 * C:\users\barrybo\mitls2c\kremlin\_build\src\Kremlin.native -minimal -fnouint128 C:/users/barrybo/mitls2c/FStar/ulib/FStar.UInt128.fst -tmpdir ../secure_api/out/runtime_switch/uint128 -skip-compilation -add-include "kremlib0.h" -drop FStar.Int.Cast.Full -bundle FStar.UInt128=FStar.*,Prims
 * F* version: 15104ff8
 * KreMLin version: 318b7fa8
 */
#include "kremlin/internal/types.h"
#include "FStar_UInt128.h"
#include "FStar_UInt_8_16_32_64.h"

#ifndef _MSC_VER
#  error This file only works with the MSVC compiler
#endif

#if defined(_M_X64) && !defined(KRML_VERIFIED_UINT128)
#define HAS_OPTIMIZED 1
#else
#define HAS_OPTIMIZED 0
#endif

// Define .low and .high in terms of the __m128i fields, to reduce
// the amount of churn in this file.
#if HAS_OPTIMIZED
#include <intrin.h>
#include <immintrin.h>
#define low m128i_u64[0]
#define high m128i_u64[1]
#endif

inline static FStar_UInt128_uint128 load128_le(uint8_t *b) {
#if HAS_OPTIMIZED
  return _mm_loadu_si128((__m128i *)b);
#else
  return (
      (FStar_UInt128_uint128){ .low = load64_le(b), .high = load64_le(b + 8) });
#endif
}

inline static void store128_le(uint8_t *b, FStar_UInt128_uint128 n) {
  store64_le(b, n.low);
  store64_le(b + 8, n.high);
}

inline static FStar_UInt128_uint128 load128_be(uint8_t *b) {
  uint64_t l = load64_be(b + 8);
  uint64_t h = load64_be(b);
#if HAS_OPTIMIZED
  return _mm_set_epi64x(h, l);
#else
  return ((FStar_UInt128_uint128){ .low = l, .high = h });
#endif
}

inline static void store128_be(uint8_t *b, uint128_t n) {
  store64_be(b, n.high);
  store64_be(b + 8, n.low);
}

inline static uint64_t FStar_UInt128_constant_time_carry(uint64_t a, uint64_t b) {
  return (a ^ (a ^ b | a - b ^ b)) >> (uint32_t)63U;
}

inline static uint64_t FStar_UInt128_carry(uint64_t a, uint64_t b) {
  return FStar_UInt128_constant_time_carry(a, b);
}

inline static FStar_UInt128_uint128
FStar_UInt128_add(FStar_UInt128_uint128 a, FStar_UInt128_uint128 b) {
#if HAS_OPTIMIZED
  uint64_t l, h;

  unsigned char carry =
      _addcarry_u64(0, a.low, b.low, &l);   // low/CF = a.low+b.low+0
  _addcarry_u64(carry, a.high, b.high, &h); // high   = a.high+b.high+CF
  return _mm_set_epi64x(h, l);
#else
  return ((FStar_UInt128_uint128){
      .low = a.low + b.low,
      .high = a.high + b.high + FStar_UInt128_carry(a.low + b.low, b.low) });
#endif
}

inline static FStar_UInt128_uint128
FStar_UInt128_add_underspec(FStar_UInt128_uint128 a, FStar_UInt128_uint128 b) {
#if HAS_OPTIMIZED
  return FStar_UInt128_add(a, b);
#else
  return ((FStar_UInt128_uint128){
      .low = a.low + b.low,
      .high = FStar_UInt64_add_underspec(
          FStar_UInt64_add_underspec(a.high, b.high),
          FStar_UInt128_carry(a.low + b.low, b.low)) });
#endif
}

inline static FStar_UInt128_uint128
FStar_UInt128_add_mod(FStar_UInt128_uint128 a, FStar_UInt128_uint128 b) {
#if HAS_OPTIMIZED
  return FStar_UInt128_add(a, b);
#else
  return ((FStar_UInt128_uint128){
      .low = a.low + b.low,
      .high = a.high + b.high + FStar_UInt128_carry(a.low + b.low, b.low) });
#endif
}

inline static FStar_UInt128_uint128
FStar_UInt128_sub(FStar_UInt128_uint128 a, FStar_UInt128_uint128 b) {
#if HAS_OPTIMIZED
  uint64_t l, h;

  unsigned char borrow = _subborrow_u64(0, a.low, b.low, &l);
  _subborrow_u64(borrow, a.high, b.high, &h);
  return _mm_set_epi64x(h, l);
#else
  return ((FStar_UInt128_uint128){
      .low = a.low - b.low,
      .high = a.high - b.high - FStar_UInt128_carry(a.low, a.low - b.low) });
#endif
}

inline static FStar_UInt128_uint128
FStar_UInt128_sub_underspec(FStar_UInt128_uint128 a, FStar_UInt128_uint128 b) {
#if HAS_OPTIMIZED
  return FStar_UInt128_sub(a, b);
#else
  return ((FStar_UInt128_uint128){
      .low = a.low - b.low,
      .high = FStar_UInt64_sub_underspec(
          FStar_UInt64_sub_underspec(a.high, b.high),
          FStar_UInt128_carry(a.low, a.low - b.low)) });
#endif
}

inline static FStar_UInt128_uint128
FStar_UInt128_sub_mod_impl(FStar_UInt128_uint128 a, FStar_UInt128_uint128 b) {
  return ((FStar_UInt128_uint128){
      .low = a.low - b.low,
      .high = a.high - b.high - FStar_UInt128_carry(a.low, a.low - b.low) });
}

inline static FStar_UInt128_uint128
FStar_UInt128_sub_mod(FStar_UInt128_uint128 a, FStar_UInt128_uint128 b) {
#if HAS_OPTIMIZED
  return FStar_UInt128_sub(a, b);
#else
  return FStar_UInt128_sub_mod_impl(a, b);
#endif
}

inline static FStar_UInt128_uint128
FStar_UInt128_logand(FStar_UInt128_uint128 a, FStar_UInt128_uint128 b) {
#if HAS_OPTIMIZED
  return _mm_and_si128(a, b);
#else
  return (
      (FStar_UInt128_uint128){ .low = a.low & b.low, .high = a.high & b.high });
#endif
}

inline static FStar_UInt128_uint128
FStar_UInt128_logxor(FStar_UInt128_uint128 a, FStar_UInt128_uint128 b) {
#if HAS_OPTIMIZED
  return _mm_xor_si128(a, b);
#else
  return (
      (FStar_UInt128_uint128){ .low = a.low ^ b.low, .high = a.high ^ b.high });
#endif
}

inline static FStar_UInt128_uint128
FStar_UInt128_logor(FStar_UInt128_uint128 a, FStar_UInt128_uint128 b) {
#if HAS_OPTIMIZED
  return _mm_or_si128(a, b);
#else
  return (
      (FStar_UInt128_uint128){ .low = a.low | b.low, .high = a.high | b.high });
#endif
}

inline static FStar_UInt128_uint128 FStar_UInt128_lognot(FStar_UInt128_uint128 a) {
#if HAS_OPTIMIZED
  return _mm_andnot_si128(a, a);
#else
  return ((FStar_UInt128_uint128){ .low = ~a.low, .high = ~a.high });
#endif
}

static const uint32_t FStar_UInt128_u32_64 = (uint32_t)64U;

inline static uint64_t
FStar_UInt128_add_u64_shift_left(uint64_t hi, uint64_t lo, uint32_t s) {
  return (hi << s) + (lo >> FStar_UInt128_u32_64 - s);
}

inline static uint64_t
FStar_UInt128_add_u64_shift_left_respec(uint64_t hi, uint64_t lo, uint32_t s) {
  return FStar_UInt128_add_u64_shift_left(hi, lo, s);
}

inline static FStar_UInt128_uint128
FStar_UInt128_shift_left_small(FStar_UInt128_uint128 a, uint32_t s) {
  if (s == (uint32_t)0U)
    return a;
  else
    return ((FStar_UInt128_uint128){
        .low = a.low << s,
        .high = FStar_UInt128_add_u64_shift_left_respec(a.high, a.low, s) });
}

inline static FStar_UInt128_uint128
FStar_UInt128_shift_left_large(FStar_UInt128_uint128 a, uint32_t s) {
  return ((FStar_UInt128_uint128){ .low = (uint64_t)0U,
                                   .high = a.low << s - FStar_UInt128_u32_64 });
}

inline static FStar_UInt128_uint128
FStar_UInt128_shift_left(FStar_UInt128_uint128 a, uint32_t s) {
#if HAS_OPTIMIZED
  if (s == 0) {
    return a;
  } else if (s < FStar_UInt128_u32_64) {
    uint64_t l = a.low << s;
    uint64_t h = __shiftleft128(a.low, a.high, (unsigned char)s);
    return _mm_set_epi64x(h, l);
  } else {
    return _mm_set_epi64x(a.low << (s - FStar_UInt128_u32_64), 0);
  }
#else
  if (s < FStar_UInt128_u32_64)
    return FStar_UInt128_shift_left_small(a, s);
  else
    return FStar_UInt128_shift_left_large(a, s);
#endif
}

inline static uint64_t
FStar_UInt128_add_u64_shift_right(uint64_t hi, uint64_t lo, uint32_t s) {
  return (lo >> s) + (hi << FStar_UInt128_u32_64 - s);
}

inline static uint64_t
FStar_UInt128_add_u64_shift_right_respec(uint64_t hi, uint64_t lo, uint32_t s) {
  return FStar_UInt128_add_u64_shift_right(hi, lo, s);
}

inline static FStar_UInt128_uint128
FStar_UInt128_shift_right_small(FStar_UInt128_uint128 a, uint32_t s) {
  if (s == (uint32_t)0U)
    return a;
  else
    return ((FStar_UInt128_uint128){
        .low = FStar_UInt128_add_u64_shift_right_respec(a.high, a.low, s),
        .high = a.high >> s });
}

inline static FStar_UInt128_uint128
FStar_UInt128_shift_right_large(FStar_UInt128_uint128 a, uint32_t s) {
  return ((FStar_UInt128_uint128){ .low = a.high >> s - FStar_UInt128_u32_64,
                                   .high = (uint64_t)0U });
}

inline static FStar_UInt128_uint128
FStar_UInt128_shift_right(FStar_UInt128_uint128 a, uint32_t s) {
#if HAS_OPTIMIZED
  if (s == 0) {
    return a;
  } else if (s < FStar_UInt128_u32_64) {
    uint64_t l = __shiftright128(a.low, a.high, (unsigned char)s);
    uint64_t h = a.high >> s;
    return _mm_set_epi64x(h, l);
  } else {
    return _mm_set_epi64x(0, a.high >> (s - FStar_UInt128_u32_64));
  }
#else
  if (s < FStar_UInt128_u32_64)
    return FStar_UInt128_shift_right_small(a, s);
  else
    return FStar_UInt128_shift_right_large(a, s);
#endif
}

inline static bool FStar_UInt128_eq(FStar_UInt128_uint128 a, FStar_UInt128_uint128 b) {
  return a.low == b.low && a.high == b.high;
}

inline static bool FStar_UInt128_gt(FStar_UInt128_uint128 a, FStar_UInt128_uint128 b) {
  return a.high > b.high || a.high == b.high && a.low > b.low;
}

inline static bool FStar_UInt128_lt(FStar_UInt128_uint128 a, FStar_UInt128_uint128 b) {
  return a.high < b.high || a.high == b.high && a.low < b.low;
}

inline static bool FStar_UInt128_gte(FStar_UInt128_uint128 a, FStar_UInt128_uint128 b) {
  return a.high > b.high || a.high == b.high && a.low >= b.low;
}

inline static bool FStar_UInt128_lte(FStar_UInt128_uint128 a, FStar_UInt128_uint128 b) {
  return a.high < b.high || a.high == b.high && a.low <= b.low;
}

inline static FStar_UInt128_uint128
FStar_UInt128_eq_mask(FStar_UInt128_uint128 a, FStar_UInt128_uint128 b) {
#if HAS_OPTIMIZED
  // PCMPW to produce 4 32-bit values, all either 0x0 or 0xffffffff
  __m128i r32 = _mm_cmpeq_epi32(a, b);
  // Shuffle 3,2,1,0 into 2,3,0,1 (swapping dwords inside each half)
  __m128i s32 = _mm_shuffle_epi32(r32, _MM_SHUFFLE(2, 3, 0, 1));
  // Bitwise and to compute (3&2),(2&3),(1&0),(0&1)
  __m128i ret64 = _mm_and_si128(r32, s32);
  // Swap the two 64-bit values to form s64
  __m128i s64 =
      _mm_shuffle_epi32(ret64, _MM_SHUFFLE(1, 0, 3, 2)); // 3,2,1,0 -> 1,0,3,2
  // And them together
  return _mm_and_si128(ret64, s64);
#else
  return (
      (FStar_UInt128_uint128){ .low = FStar_UInt64_eq_mask(a.low, b.low) &
                                      FStar_UInt64_eq_mask(a.high, b.high),
                               .high = FStar_UInt64_eq_mask(a.low, b.low) &
                                       FStar_UInt64_eq_mask(a.high, b.high) });
#endif
}

inline static FStar_UInt128_uint128
FStar_UInt128_gte_mask(FStar_UInt128_uint128 a, FStar_UInt128_uint128 b) {
#if HAS_OPTIMIZED && 0
  // ge - compare 3,2,1,0 for >= and generating 0 or 0xffffffff for each
  // eq - compare 3,2,1,0 for == and generating 0 or 0xffffffff for each
  // slot 0 = ge0 | (eq0 & ge1) | (eq0 & eq1 & ge2) | (eq0 & eq1 & eq2 & ge3)
  // then splat slot 0 to 3,2,1,0
  __m128i gt = _mm_cmpgt_epi32(a, b);
  __m128i eq = _mm_cmpeq_epi32(a, b);
  __m128i ge = _mm_or_si128(gt, eq);
  __m128i ge0 = ge;
  __m128i eq0 = eq;
  __m128i ge1 = _mm_srli_si128(ge, 4); // shift ge from 3,2,1,0 to 0x0,3,2,1
  __m128i t1 = _mm_and_si128(eq0, ge1);
  __m128i ret = _mm_or_si128(ge, t1);  // ge0 | (eq0 & ge1) is now in 0
  __m128i eq1 = _mm_srli_si128(eq, 4); // shift eq from 3,2,1,0 to 0x0,3,2,1
  __m128i ge2 =
      _mm_srli_si128(ge1, 4); // shift original ge from 3,2,1,0 to 0x0,0x0,3,2
  __m128i t2 =
      _mm_and_si128(eq0, _mm_and_si128(eq1, ge2)); // t2 = (eq0 & eq1 & ge2)
  ret = _mm_or_si128(ret, t2);
  __m128i eq2 = _mm_srli_si128(eq1, 4); // shift eq from 3,2,1,0 to 0x0,00,00,3
  __m128i ge3 =
      _mm_srli_si128(ge2, 4); // shift original ge from 3,2,1,0 to 0x0,0x0,0x0,3
  __m128i t3 = _mm_and_si128(
      eq0, _mm_and_si128(
               eq1, _mm_and_si128(eq2, ge3))); // t3 = (eq0 & eq1 & eq2 & ge3)
  ret = _mm_or_si128(ret, t3);
  return _mm_shuffle_epi32(
      ret,
      _MM_SHUFFLE(0, 0, 0, 0)); // the result is in 0.  Shuffle into all dwords.
#else
  return ((FStar_UInt128_uint128){
      .low = FStar_UInt64_gte_mask(a.high, b.high) &
                 ~FStar_UInt64_eq_mask(a.high, b.high) |
             FStar_UInt64_eq_mask(a.high, b.high) &
                 FStar_UInt64_gte_mask(a.low, b.low),
      .high = FStar_UInt64_gte_mask(a.high, b.high) &
                  ~FStar_UInt64_eq_mask(a.high, b.high) |
              FStar_UInt64_eq_mask(a.high, b.high) &
                  FStar_UInt64_gte_mask(a.low, b.low) });
#endif
}

inline static FStar_UInt128_uint128 FStar_UInt128_uint64_to_uint128(uint64_t a) {
#if HAS_OPTIMIZED
  return _mm_set_epi64x(0, a);
#else
  return ((FStar_UInt128_uint128){ .low = a, .high = (uint64_t)0U });
#endif
}

inline static uint64_t FStar_UInt128_uint128_to_uint64(FStar_UInt128_uint128 a) {
  return a.low;
}

inline static uint64_t FStar_UInt128_u64_mod_32(uint64_t a) {
  return a & (uint64_t)0xffffffffU;
}

static uint32_t FStar_UInt128_u32_32 = (uint32_t)32U;

inline static uint64_t FStar_UInt128_u32_combine(uint64_t hi, uint64_t lo) {
  return lo + (hi << FStar_UInt128_u32_32);
}

inline static FStar_UInt128_uint128 FStar_UInt128_mul32(uint64_t x, uint32_t y) {
#if HAS_OPTIMIZED
  uint64_t l, h;
  l = _umul128(x, (uint64_t)y, &h);
  return _mm_set_epi64x(h, l);
#else
  return ((FStar_UInt128_uint128){
      .low = FStar_UInt128_u32_combine(
          (x >> FStar_UInt128_u32_32) * (uint64_t)y +
              (FStar_UInt128_u64_mod_32(x) * (uint64_t)y >>
               FStar_UInt128_u32_32),
          FStar_UInt128_u64_mod_32(FStar_UInt128_u64_mod_32(x) * (uint64_t)y)),
      .high = (x >> FStar_UInt128_u32_32) * (uint64_t)y +
                  (FStar_UInt128_u64_mod_32(x) * (uint64_t)y >>
                   FStar_UInt128_u32_32) >>
              FStar_UInt128_u32_32 });
#endif
}

/* Note: static headers bring scope collision issues when they define types!
 * Because now client (kremlin-generated) code will include this header and
 * there might be type collisions if the client code uses quadruples of uint64s.
 * So, we cannot use the kremlin-generated name. */
typedef struct K_quad_s {
  uint64_t fst;
  uint64_t snd;
  uint64_t thd;
  uint64_t f3;
} K_quad;

inline static K_quad
FStar_UInt128_mul_wide_impl_t_(uint64_t x, uint64_t y) {
  return ((K_quad){
      .fst = FStar_UInt128_u64_mod_32(x),
      .snd = FStar_UInt128_u64_mod_32(
          FStar_UInt128_u64_mod_32(x) * FStar_UInt128_u64_mod_32(y)),
      .thd = x >> FStar_UInt128_u32_32,
      .f3 = (x >> FStar_UInt128_u32_32) * FStar_UInt128_u64_mod_32(y) +
            (FStar_UInt128_u64_mod_32(x) * FStar_UInt128_u64_mod_32(y) >>
             FStar_UInt128_u32_32) });
}

static uint64_t FStar_UInt128_u32_combine_(uint64_t hi, uint64_t lo) {
  return lo + (hi << FStar_UInt128_u32_32);
}

inline static FStar_UInt128_uint128
FStar_UInt128_mul_wide_impl(uint64_t x, uint64_t y) {
  K_quad scrut =
      FStar_UInt128_mul_wide_impl_t_(x, y);
  uint64_t u1 = scrut.fst;
  uint64_t w3 = scrut.snd;
  uint64_t x_ = scrut.thd;
  uint64_t t_ = scrut.f3;
  return ((FStar_UInt128_uint128){
      .low = FStar_UInt128_u32_combine_(
          u1 * (y >> FStar_UInt128_u32_32) + FStar_UInt128_u64_mod_32(t_), w3),
      .high =
          x_ * (y >> FStar_UInt128_u32_32) + (t_ >> FStar_UInt128_u32_32) +
          (u1 * (y >> FStar_UInt128_u32_32) + FStar_UInt128_u64_mod_32(t_) >>
           FStar_UInt128_u32_32) });
}

inline static
FStar_UInt128_uint128 FStar_UInt128_mul_wide(uint64_t x, uint64_t y) {
#if HAS_OPTIMIZED
  uint64_t l, h;
  l = _umul128(x, y, &h);
  return _mm_set_epi64x(h, l);
#else
  return FStar_UInt128_mul_wide_impl(x, y);
#endif
}
