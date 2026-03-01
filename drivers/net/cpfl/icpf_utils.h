/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2001-2022 Intel Corporation
 */

#ifndef _ICPF_UTILS_H_
#define _ICPF_UTILS_H_

/* Common Bit Mask Macros */
#define ICPF_BIT(b)			(1 << (b))

#define MAKE_MASK(type, mask, shift)	((u##type) (mask) << (shift))
#define SHIFT_VAL_LT(type, val, field)		\
		(((u##type)(val) << field##_S) & field##_M)
#define SHIFT_VAL_RT(type, val, field)		\
		(((u##type)(val) & field##_M) >> field##_S)

#define MAKE_MASK_VAL(type, bit_len)	(((u##type)0x01 << (bit_len)) - 1)
#define MAKE_MASK_VAL16(bit_len)	MAKE_MASK_VAL(16, bit_len)
#define MAKE_MASK_VAL64(bit_len)	MAKE_MASK_VAL(64, bit_len)

#define MAKE_MASK64(mask, shift)	MAKE_MASK(64, mask, shift)
#define MAKE_MASK16(mask, shift)	MAKE_MASK(16, mask, shift)
#define MAKE_MASK32(mask, shift)	MAKE_MASK(32, mask, shift)

/* Make masks with bit length and left-shifting count */
#define MAKE_SMASK(type, bits, shift)	\
	((((u##type)1 << (bits)) - 1) << (shift))
#define MAKE_SMASK64(bits, shift)	MAKE_SMASK(64, bits, shift)
#define MAKE_SMASK32(bits, shift)	MAKE_SMASK(32, bits, shift)
#define MAKE_SMASK16(bits, shift)	MAKE_SMASK(16, bits, shift)

#define SHIFT_VAL64(val, field)		SHIFT_VAL_LT(64, val, field)
#define SHIFT_VAL32(val, field)		SHIFT_VAL_LT(32, val, field)
#define SHIFT_VAL16(val, field)		SHIFT_VAL_LT(16, val, field)

/* Transformation and bitmap */
#define DIVIDE_AND_ROUND_UP(a, b)	(((a) + (b) - 1) / (b))
#define ROUND_UP(a, b)			(((a) + (b) - 1) / (b) * (b))

#define BITS_IN_BYTE			8
#define BITS_TO_BYTE_CHUNKS(sz)		DIVIDE_AND_ROUND_UP((sz), BITS_IN_BYTE)

#define ICPF_BMP_BIT_CHUNK(nr)		((nr) / BITS_IN_BYTE)
#define ICPF_BMP_BIT_IN_CHUNK(nr)	ICPF_BIT((nr) % BITS_IN_BYTE)

#define icpf_declare_bitmap(A, sz) u8 A[BITS_TO_BYTE_CHUNKS(sz)]

/**
 * icpf_bmp_is_bit_set - Indicate if a given bit is set in the bitmap
 *
 * @bmp: Pointer to a bitmap
 * @pos: Bit position to check
 * @nbits: Size of bitmap in bits
 */
static inline bool icpf_bmp_is_bit_set(const u8 *bmp, u32 pos, u32 nbits)
{
	return pos < nbits ?
		(bmp[ICPF_BMP_BIT_CHUNK(pos)] & ICPF_BMP_BIT_IN_CHUNK(pos)) :
		false;
}

/**
 * icpf_bmp_set_bit - Set a bit in a bitmap
 *
 * @bmp: Pointer to a bitmap
 * @pos: Bit position to set
 * @nbits: Size of bitmap in bits
 */
static inline void icpf_bmp_set_bit(u8 *bmp, u32 pos, u32 nbits)
{
	if (pos < nbits)
		bmp[ICPF_BMP_BIT_CHUNK(pos)] |= ICPF_BMP_BIT_IN_CHUNK(pos);
}

/**
 * icpf_bmp_clear_bit - Clear a bit in a bitmap
 *
 * @bmp: Pointer to a bitmap
 * @pos: Bit position to clear
 * @nbits: Size of bitmap in bits
 */
static inline void icpf_bmp_clear_bit(u8 *bmp, u32 pos, u32 nbits)
{
	if (pos < nbits)
		bmp[ICPF_BMP_BIT_CHUNK(pos)] &= ~ICPF_BMP_BIT_IN_CHUNK(pos);
}

/*
 * icpf_bmp_is_empty - check if bitmap is empty (all bits are 0s)
 *
 * @bmp: Pointer to the bitmap
 * @nbits: Size of bitmap in bits
 */
static inline bool icpf_bmp_is_empty(const u8 *bmp, u32 nbits)
{
	u16 end_idx;
	u8 bits;
	u8 mask;
	u16 i;

	bits = nbits % BITS_IN_BYTE;
	end_idx = (nbits == 0) ? 0 : (nbits - 1) / BITS_IN_BYTE;
	mask = (bits == 0) ? 0xff : (u8)0xff >> (BITS_IN_BYTE - bits);

	/* Check the last byte */
	if (bmp[end_idx] & mask)
		return false;

	/* Check the rest of the bytes */
	for (i = 0; i < end_idx; i++)
		if (bmp[i])
			return false;

	return true;
}

#endif /* _ICPF_UTILS_H_ */
