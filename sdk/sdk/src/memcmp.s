// memcmp for RV64IM, written for Pico: every load is naturally aligned. A misaligned access runs,
// but each one is proven on the MemoryUnaligned chip, which holds few rows per chunk. `bcmp` is
// the same function.
//
// When the two pointers sit at the same offset within a word and n >= 8: one byte at a time up
// to the word boundary, then 8 bytes a step in `ld`. A word that differs is compared again one
// byte at a time, which finds the first differing byte within it. Otherwise, and for the last
// 0 to 7 bytes, one byte at a time. The result is the first differing pair's difference as
// unsigned bytes, or 0.

	.text
	.attribute	5, "rv64i2p1_m2p0_zmmul1p0"
	.globl	memcmp
	.p2align	2
	.type	memcmp,@function
// a0 = s1, a1 = s2, a2 = n; returns in a0.
memcmp:
	li	t0, 8
	bltu	a2, t0, .Lmemcmp_bytes
	xor	t1, a0, a1
	andi	t1, t1, 7
	bnez	t1, .Lmemcmp_bytes
	andi	t1, a0, 7
	beqz	t1, .Lmemcmp_words
	// Up to the word boundary (n >= 8 > the head).
.Lmemcmp_head:
	lbu	t2, 0(a0)
	lbu	t3, 0(a1)
	bne	t2, t3, .Lmemcmp_differ
	addi	a0, a0, 1
	addi	a1, a1, 1
	addi	a2, a2, -1
	andi	t1, a0, 7
	bnez	t1, .Lmemcmp_head
.Lmemcmp_words:
	bltu	a2, t0, .Lmemcmp_bytes
.Lmemcmp_word:
	ld	t2, 0(a0)
	ld	t3, 0(a1)
	// n >= 8 here, so the byte loop finds the difference within this word.
	bne	t2, t3, .Lmemcmp_byte
	addi	a0, a0, 8
	addi	a1, a1, 8
	addi	a2, a2, -8
	bgeu	a2, t0, .Lmemcmp_word

.Lmemcmp_bytes:
	beqz	a2, .Lmemcmp_equal
.Lmemcmp_byte:
	lbu	t2, 0(a0)
	lbu	t3, 0(a1)
	bne	t2, t3, .Lmemcmp_differ
	addi	a0, a0, 1
	addi	a1, a1, 1
	addi	a2, a2, -1
	bnez	a2, .Lmemcmp_byte
.Lmemcmp_equal:
	li	a0, 0
	ret
.Lmemcmp_differ:
	sub	a0, t2, t3
	ret
.Lmemcmp_end:
	.size	memcmp, .Lmemcmp_end-memcmp

	.globl	bcmp
	.set	bcmp, memcmp
