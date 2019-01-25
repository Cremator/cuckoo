#ifndef INCLUDE_SIPHASHXN_H
#define INCLUDE_SIPHASHXN_H
#include <altivec.h> 
#include "vec128int.h"

#ifdef __VSX__

#define ADD(a, b) vec_add2sd(a, b)
#define XOR(a, b) vec_bitxor1q(a, b)
#define ROT13(x) vec_bitor1q(vec_shiftrightimmediate2sd(x,13),vec_shiftleftimmediate2sd(x,51))
#define ROT16(x) vec_permuteupper4sh(vec_permutelower4sh(x, _MM_SHUFFLE(2,1,0,3)), _MM_SHUFFLE(2,1,0,3))
#define ROT17(x) vec_bitor1q(vec_shiftrightimmediate2sd(x,17),vec_shiftleftimmediate2sd(x,47))
#define ROT21(x) vec_bitor1q(vec_shiftrightimmediate2sd(x,21),vec_shiftleftimmediate2sd(x,43))
#define ROT32(x) vec_permute4sw(x, _MM_SHUFFLE(2,3,0,1))
typedef vector unsigned int vtype32;
typedef vector unsigned long vtype64;
typedef union {
	vtype32 v32;
	vtype64 v64;
	uint32_t s32;
	uint64_t s64;
} vtype;
#define vset1_epi64(x) vset_epi64(x, x)
#define vset_epi64(x1,x0) (vtype)(vtype64){x0, x1}
#endif

#define SIPROUNDXN \
  do { \
    v0 = ADD(v0,v1); v2 = ADD(v2,v3); v1 = ROT13(v1); \
    v3 = ROT16(v3);  v1 = XOR(v1,v0); v3 = XOR(v3,v2); \
    v0 = ROT32(v0);  v2 = ADD(v2,v1); v0 = ADD(v0,v3); \
    v1 = ROT17(v1);                   v3 = ROT21(v3); \
    v1 = XOR(v1,v2); v3 = XOR(v3,v0); v2 = ROT32(v2); \
  } while(0)

#define SIPROUNDX2N \
  do { \
    v0 = ADD(v0,v1); v4 = ADD(v4,v5); \
    v2 = ADD(v2,v3); v6 = ADD(v6,v7); \
    v1 = ROT13(v1);  v5 = ROT13(v5); \
    v3 = ROT16(v3);  v7 = ROT16(v7); \
    v1 = XOR(v1,v0); v5 = XOR(v5,v4); \
    v3 = XOR(v3,v2); v7 = XOR(v7,v6); \
    v0 = ROT32(v0);  v4 = ROT32(v4); \
    v2 = ADD(v2,v1); v6 = ADD(v6,v5); \
    v0 = ADD(v0,v3); v4 = ADD(v4,v7); \
    v1 = ROT17(v1);  v5 = ROT17(v5); \
    v3 = ROT21(v3);  v7 = ROT21(v7); \
    v1 = XOR(v1,v2); v5 = XOR(v5,v6); \
    v3 = XOR(v3,v0); v7 = XOR(v7,v4); \
    v2 = ROT32(v2);  v6 = ROT32(v6); \
  } while(0)
 
#define SIPROUNDX4N \
  do { \
    v0 = ADD(v0,v1); v4 = ADD(v4,v5);  v8 = ADD(v8,v9); vC = ADD(vC,vD); \
    v2 = ADD(v2,v3); v6 = ADD(v6,v7);  vA = ADD(vA,vB); vE = ADD(vE,vF); \
    v1 = ROT13(v1);  v5 = ROT13(v5);   v9 = ROT13(v9);  vD = ROT13(vD); \
    v3 = ROT16(v3);  v7 = ROT16(v7);   vB = ROT16(vB);  vF = ROT16(vF); \
    v1 = XOR(v1,v0); v5 = XOR(v5,v4);  v9 = XOR(v9,v8); vD = XOR(vD,vC); \
    v3 = XOR(v3,v2); v7 = XOR(v7,v6);  vB = XOR(vB,vA); vF = XOR(vF,vE); \
    v0 = ROT32(v0);  v4 = ROT32(v4);   v8 = ROT32(v8);  vC = ROT32(vC); \
    v2 = ADD(v2,v1); v6 = ADD(v6,v5);  vA = ADD(vA,v9); vE = ADD(vE,vD); \
    v0 = ADD(v0,v3); v4 = ADD(v4,v7);  v8 = ADD(v8,vB); vC = ADD(vC,vF); \
    v1 = ROT17(v1);  v5 = ROT17(v5);   v9 = ROT17(v9);  vD = ROT17(vD); \
    v3 = ROT21(v3);  v7 = ROT21(v7);   vB = ROT21(vB);  vF = ROT21(vF); \
    v1 = XOR(v1,v2); v5 = XOR(v5,v6);  v9 = XOR(v9,vA); vD = XOR(vD,vE); \
    v3 = XOR(v3,v0); v7 = XOR(v7,v4);  vB = XOR(vB,v8); vF = XOR(vF,vC); \
    v2 = ROT32(v2);  v6 = ROT32(v6);   vA = ROT32(vA);  vE = ROT32(vE); \
  } while(0)


#ifdef __VSX__

// 2-way sipHash-2-4 specialized to precomputed key and 8 byte nonces
void siphash24x2(const siphash_keys *keys, const uint64_t *indices, uint64_t *hashes) {
  __m128i v0, v1, v2, v3, mi;
  v0 = vset1_epi64(keys->k0);
  v1 = vset1_epi64(keys->k1);
  v2 = vset1_epi64(keys->k2);
  v3 = vset1_epi64(keys->k3);
  mi = vset1_epi64((__m128i *)indices);
	
  v3 = XOR (v3, mi);
  SIPROUNDXN; SIPROUNDXN;
  v0 = XOR (v0, mi);
  
  v2 = XOR (v2, _mm_set1_epi64x(0xffLL));
  SIPROUNDXN; SIPROUNDXN; SIPROUNDXN; SIPROUNDXN;
  mi = XOR(XOR(v0,v1),XOR(v2,v3));
  
  _mm_store_si128((__m128i *)hashes, mi);
}

// 4-way sipHash-2-4 specialized to precomputed key and 8 byte nonces
void siphash24x4(const siphash_keys *keys, const uint64_t *indices, uint64_t *hashes) {
  __m128i v0, v1, v2, v3, mi, v4, v5, v6, v7, m2;
  v4 = v0 = vset1_epi64(keys->k0);
  v5 = v1 = vset1_epi64(keys->k1);
  v6 = v2 = vset1_epi64(keys->k2);
  v7 = v3 = vset1_epi64(keys->k3);

  mi = vec_load1q((__m128i *)indices);
  m2 = vec_load1q((__m128i *)(indices + 2));

  v3 = XOR (v3, mi);
  v7 = XOR (v7, m2);
  SIPROUNDX2N; SIPROUNDX2N;
  v0 = XOR (v0, mi);
  v4 = XOR (v4, m2);

  v2 = XOR (v2, vset1_epi64(0xffLL));
  v6 = XOR (v6, vset1_epi64(0xffLL));
  SIPROUNDX2N; SIPROUNDX2N; SIPROUNDX2N; SIPROUNDX2N;
  mi = XOR(XOR(v0,v1),XOR(v2,v3));
  m2 = XOR(XOR(v4,v5),XOR(v6,v7));
  
  vec_store1q((__m128i *)hashes,		mi);
  vec_store1q((__m128i *)(hashes + 2),m2);
}
#endif

#ifndef NSIPHASH
// how many siphash24 to compute in parallel
// currently 1, 2, 4, 8 are supported, but
// more than 1 requires the use of sse2 or avx2
// more than 4 requires the use of avx2
#define NSIPHASH 1
#endif

void siphash24xN(const siphash_keys *keys, const uint64_t *indices, uint64_t * hashes) {
#if NSIPHASH == 1
  *hashes = keys->siphash24(*indices);
#elif NSIPHASH == 2  
  siphash24x2(keys, indices, hashes); 
#elif NSIPHASH == 4
  siphash24x4(keys, indices, hashes);
#elif NSIPHASH == 8
  siphash24x8(keys, indices, hashes);
#elif NSIPHASH == 16
  siphash24x16(keys, indices, hashes);
#else
#error not implemented
#endif
}

#endif // ifdef INCLUDE_SIPHASHXN_H
