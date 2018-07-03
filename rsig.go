package prekeyserver

import (
	"github.com/twstrike/ed448"
)

type ringSignature struct {
	c1 ed448.Scalar
	r1 ed448.Scalar
	c2 ed448.Scalar
	r2 ed448.Scalar
	c3 ed448.Scalar
	r3 ed448.Scalar
}

func generateZqKeypair(r WithRandom) (ed448.Scalar, ed448.Point) {
	sym := [symKeyLength]byte{}
	randomInto(r, sym[:])
	return deriveZqKeypair(sym)
}

func deriveZqKeypair(sym [symKeyLength]byte) (ed448.Scalar, ed448.Point) {
	kp := deriveEDDSAKeypair(sym)
	return kp.priv.k, kp.pub.k
}

func blah(ed448.Scalar, ed448.Point) {
}

// mask is a uint64_t or uint32_t depending on arch
//  * On the flip side, mask_t is always -1 or 0, but it might be a different size * than goldilocks_bool_t.

// void API_NS(point_cond_sel) (
//     point_p out,
//     const point_p a,
//     const point_p b,
//     goldilocks_bool_t pick_b
// ) {
//     constant_time_select(out,a,b,sizeof(point_p),bool_to_mask(pick_b),0);
// }

// static __inline__ void
// __attribute__((unused,always_inline))
// constant_time_select (
//     void *a_,
//     const void *bFalse_,
//     const void *bTrue_,
//     word_t elem_bytes,
//     mask_t mask,
//     size_t alignment_bytes
// ) {
//     unsigned char *a = (unsigned char *)a_;
//     const unsigned char *bTrue = (const unsigned char *)bTrue_;
//     const unsigned char *bFalse = (const unsigned char *)bFalse_;

//     alignment_bytes |= elem_bytes;

//     word_t k;
//     big_register_t br_mask = br_set_to_mask(mask);
//     for (k=0; k<=elem_bytes-sizeof(big_register_t); k+=sizeof(big_register_t)) {
//         if (alignment_bytes % sizeof(big_register_t)) {
//             /* unaligned */
//             ((unaligned_br_s*)(&a[k]))->unaligned =
// 		  ( br_mask & ((const unaligned_br_s*)(&bTrue [k]))->unaligned)
// 		| (~br_mask & ((const unaligned_br_s*)(&bFalse[k]))->unaligned);
//         } else {
//             /* aligned */
//             *(big_register_t *)(a+k) =
// 		  ( br_mask & *(const big_register_t*)(&bTrue [k]))
// 		| (~br_mask & *(const big_register_t*)(&bFalse[k]));
//         }
//     }

//     if (elem_bytes % sizeof(big_register_t) >= sizeof(word_t)) {
//         for (; k<=elem_bytes-sizeof(word_t); k+=sizeof(word_t)) {
//             if (alignment_bytes % sizeof(word_t)) {
//                 /* unaligned */
//                 ((unaligned_word_s*)(&a[k]))->unaligned =
// 		    ( mask & ((const unaligned_word_s*)(&bTrue [k]))->unaligned)
// 		  | (~mask & ((const unaligned_word_s*)(&bFalse[k]))->unaligned);
//             } else {
//                 /* aligned */
//                 *(word_t *)(a+k) =
// 		    ( mask & *(const word_t*)(&bTrue [k]))
// 		  | (~mask & *(const word_t*)(&bFalse[k]));
//             }
//         }
//     }

//     if (elem_bytes % sizeof(word_t)) {
//         for (; k<elem_bytes; k+=1) {
//             a[k] = ( mask & bTrue[k]) | (~mask & bFalse[k]);
//         }
//     }
// }

func pointCondSel() {
	//	goldilocks_448_point_cond_sel
}

func scalarCondSel() {
	//	goldilocks_448_scalar_cond_sel
}

func choose_T(Ai ed448.Point, isSecret bool, Ri ed448.Point, Ti ed448.Point, ci ed448.Scalar) ed448.Point {
	chosen := ed448.PointScalarMul(Ai, ci)
	chosen.Add(Ri, chosen)

	// goldilocks_448_point_cond_sel(chosen, chosen, Ti, is_secret);
	return nil
}

func calculate_c() ed448.Scalar {
	// void otrng_rsig_calculate_c(
	//     goldilocks_448_scalar_p dst, const goldilocks_448_point_p A1,
	//     const goldilocks_448_point_p A2, const goldilocks_448_point_p A3,
	//     const goldilocks_448_point_p T1, const goldilocks_448_point_p T2,
	//     const goldilocks_448_point_p T3, const uint8_t *msg, size_t msglen) {
	//   goldilocks_shake256_ctx_p hd;
	//   uint8_t hash[HASH_BYTES];
	//   uint8_t point_buff[ED448_POINT_BYTES];

	//   hash_init_with_usage(hd, 0x1D);
	//   hash_update(hd, base_point_bytes_dup, ED448_POINT_BYTES);
	//   hash_update(hd, prime_order_bytes_dup, ED448_SCALAR_BYTES);

	//   goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff, A1);
	//   hash_update(hd, point_buff, ED448_POINT_BYTES);

	//   goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff, A2);
	//   hash_update(hd, point_buff, ED448_POINT_BYTES);

	//   goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff, A3);
	//   hash_update(hd, point_buff, ED448_POINT_BYTES);

	//   goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff, T1);
	//   hash_update(hd, point_buff, ED448_POINT_BYTES);

	//   goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff, T2);
	//   hash_update(hd, point_buff, ED448_POINT_BYTES);

	//   goldilocks_448_point_mul_by_ratio_and_encode_like_eddsa(point_buff, T3);
	//   hash_update(hd, point_buff, ED448_POINT_BYTES);

	//   hash_update(hd, msg, msglen);

	//   hash_final(hd, hash, sizeof(hash));
	//   hash_destroy(hd);

	//   goldilocks_448_scalar_decode_long(dst, hash, sizeof(hash));
	// }
}

func calculate_ci() ed448.Scalar {
	// static void calculate_ci(goldilocks_448_scalar_p dst,
	//                          const goldilocks_448_scalar_p c,
	//                          const goldilocks_448_scalar_p ci,
	//                          goldilocks_bool_t is_secret,
	//                          const goldilocks_448_scalar_p cj,
	//                          const goldilocks_448_scalar_p ck) {
	//   // if_secret = c - c2 - c3 or c - c1 - c3 or c - c1 - c2
	//   goldilocks_448_scalar_p if_secret;

	//   goldilocks_448_scalar_sub(if_secret, c, cj);
	//   goldilocks_448_scalar_sub(if_secret, if_secret, ck);
	//   goldilocks_448_scalar_cond_sel(dst, ci, if_secret, is_secret);
	// }
}

func calculate_ri() ed448.Scalar {
	// static void calculate_ri(goldilocks_448_scalar_p dst,
	//                          const goldilocks_448_scalar_p secret,
	//                          const goldilocks_448_scalar_p ri,
	//                          goldilocks_bool_t is_secret,
	//                          const goldilocks_448_scalar_p ci,
	//                          const goldilocks_448_scalar_p ti) {
	//   // if_secret = t1 - c1 * secret OR t2 - c2 * secret OR t3 - c3 * secret
	//   goldilocks_448_scalar_p if_secret;
	//   goldilocks_448_scalar_mul(if_secret, ci, secret);
	//   goldilocks_448_scalar_sub(if_secret, ti, if_secret);

	//   goldilocks_448_scalar_cond_sel(dst, ri, if_secret, is_secret);
	// }
}

func generateSignature(wr WithRandom, secret *privateKey, pub *publicKey, A1, A2, A3 *publicKey, m []byte) (*ringSignature, error) {
	is_A1 := pub.k.Equals(A1.k)
	is_A2 := pub.k.Equals(A2.k)
	is_A3 := pub.k.Equals(A3.k)

	t1, T1 := generateZqKeypair(wr)
	t2, T2 := generateZqKeypair(wr)
	t3, T3 := generateZqKeypair(wr)
	blah(t1, T1)
	blah(t2, T2)
	blah(t3, T3)

	r1, R1 := generateZqKeypair(wr)
	r2, R2 := generateZqKeypair(wr)
	r3, R3 := generateZqKeypair(wr)
	blah(r1, R1)
	blah(r2, R2)
	blah(r3, R3)

	c1, _ := generateZqKeypair(wr)
	c2, _ := generateZqKeypair(wr)
	c3, _ := generateZqKeypair(wr)

	chosen_T1 := choose_T(A1.k, is_A1, R1, T1, c1)
	chosen_T2 := choose_T(A2.k, is_A2, R2, T2, c2)
	chosen_T3 := choose_T(A3.k, is_A3, R3, T3, c3)

	// goldilocks_448_scalar_p c;
	// otrng_rsig_calculate_c(c, A1, A2, A3, chosen_T1, chosen_T2, chosen_T3, msg,
	//                        msglen);

	// goldilocks_448_scalar_p tmp_c1, tmp_c2, tmp_c3;
	// calculate_ci(tmp_c1, c, c1, is_A1, c2, c3);
	// calculate_ci(tmp_c2, c, c2, is_A2, c1, c3);
	// calculate_ci(tmp_c3, c, c3, is_A3, c1, c2);

	// goldilocks_448_scalar_copy(dst->c1, tmp_c1);
	// goldilocks_448_scalar_copy(dst->c2, tmp_c2);
	// goldilocks_448_scalar_copy(dst->c3, tmp_c3);

	// goldilocks_448_scalar_p tmp_r1, tmp_r2, tmp_r3;
	// calculate_ri(tmp_r1, secret, r1, is_A1, dst->c1, t1);
	// calculate_ri(tmp_r2, secret, r2, is_A2, dst->c2, t2);
	// calculate_ri(tmp_r3, secret, r3, is_A3, dst->c3, t3);

	// goldilocks_448_scalar_copy(dst->r1, tmp_r1);
	// goldilocks_448_scalar_copy(dst->r2, tmp_r2);
	// goldilocks_448_scalar_copy(dst->r3, tmp_r3);

	return nil, nil
}

// verify will actually do the cryptographic validation of the ring signature
func (r *ringSignature) verify() bool {
	// TODO: implement
	return false
}

func (r *ringSignature) deserialize(buf []byte) ([]byte, bool) {
	buf, r.c1, _ = deserializeScalar(buf)
	buf, r.r1, _ = deserializeScalar(buf)
	buf, r.c2, _ = deserializeScalar(buf)
	buf, r.r2, _ = deserializeScalar(buf)
	buf, r.c3, _ = deserializeScalar(buf)
	buf, r.r3, _ = deserializeScalar(buf)
	return buf, true
}

func (r *ringSignature) serialize() []byte {
	var out []byte
	out = append(out, serializeScalar(r.c1)...)
	out = append(out, serializeScalar(r.r1)...)
	out = append(out, serializeScalar(r.c2)...)
	out = append(out, serializeScalar(r.r2)...)
	out = append(out, serializeScalar(r.c3)...)
	out = append(out, serializeScalar(r.r3)...)
	return out
}

func serializeScalar(s ed448.Scalar) []byte {
	return s.Encode()
}

func deserializeScalar(buf []byte) ([]byte, ed448.Scalar, bool) {
	ts := ed448.NewScalar([]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})
	ts.Decode(buf[0:56])
	return buf[56:], ts, true

}
