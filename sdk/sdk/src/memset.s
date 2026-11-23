// memset for RV64IM, written for Pico: every store is naturally aligned. A misaligned access runs,
// but each one is proven on the MemoryUnaligned chip, which holds few rows per chunk.
//
// - Under 8 bytes: one byte at a time.
// - Otherwise the byte is copied into all eight lanes of a word, and the destination is aligned
//   with at most one `sb`, `sh` and `sw`, in that order. Then 64 bytes a step in `sd`, then 8,
//   and the last 0 to 7 bytes with `sw` / `sh` / `sb`, which the 8-aligned destination keeps
//   aligned.

	.text
	// No M instruction here, but keep the arch attribute: it is what enables M for the module-level
	// asm this file joins, and it must name rv64 (LLVM 23 switches the assembler to RV32 on
	// "rv32im" and then rejects the `ld` in `_start`).
	.attribute	5, "rv64i2p1_m2p0_zmmul1p0"
	.globl	memset
	.p2align	2
	.type	memset,@function
// a0 = dst, returned; a1 = the byte, in its low 8 bits; a2 = n. t0 walks dst.
memset:
	mv	t0, a0
	andi	a1, a1, 255
	li	t1, 8
	bltu	a2, t1, .Lmemset_bytes
	slli	t1, a1, 8
	or	a1, a1, t1
	slli	t1, a1, 16
	or	a1, a1, t1
	slli	t1, a1, 32
	or	a1, a1, t1
	// Align dst (n >= 8 > the head).
	andi	t1, t0, 1
	beqz	t1, .Lmemset_head2
	sb	a1, 0(t0)
	addi	t0, t0, 1
	addi	a2, a2, -1
.Lmemset_head2:
	andi	t1, t0, 2
	beqz	t1, .Lmemset_head4
	sh	a1, 0(t0)
	addi	t0, t0, 2
	addi	a2, a2, -2
.Lmemset_head4:
	andi	t1, t0, 4
	beqz	t1, .Lmemset_aligned
	sw	a1, 0(t0)
	addi	t0, t0, 4
	addi	a2, a2, -4
.Lmemset_aligned:
	li	t1, 64
	bltu	a2, t1, .Lmemset_8_check
.Lmemset_64:
	sd	a1, 0(t0)
	sd	a1, 8(t0)
	sd	a1, 16(t0)
	sd	a1, 24(t0)
	sd	a1, 32(t0)
	sd	a1, 40(t0)
	sd	a1, 48(t0)
	sd	a1, 56(t0)
	addi	t0, t0, 64
	addi	a2, a2, -64
	bgeu	a2, t1, .Lmemset_64
.Lmemset_8_check:
	li	t1, 8
	bltu	a2, t1, .Lmemset_tail4
.Lmemset_8:
	sd	a1, 0(t0)
	addi	t0, t0, 8
	addi	a2, a2, -8
	bgeu	a2, t1, .Lmemset_8
	// n < 8 left, at the 8-aligned t0.
.Lmemset_tail4:
	andi	t1, a2, 4
	beqz	t1, .Lmemset_tail2
	sw	a1, 0(t0)
	addi	t0, t0, 4
.Lmemset_tail2:
	andi	t1, a2, 2
	beqz	t1, .Lmemset_tail1
	sh	a1, 0(t0)
	addi	t0, t0, 2
.Lmemset_tail1:
	andi	t1, a2, 1
	beqz	t1, .Lmemset_done
	sb	a1, 0(t0)
.Lmemset_done:
	ret

.Lmemset_bytes:
	beqz	a2, .Lmemset_done
.Lmemset_byte:
	sb	a1, 0(t0)
	addi	t0, t0, 1
	addi	a2, a2, -1
	bnez	a2, .Lmemset_byte
	ret
.Lmemset_end:
	.size	memset, .Lmemset_end-memset
