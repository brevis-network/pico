// memmove.c (beside this file, with its provenance and licenses) compiled into assembly with:
// 
// clang-23 --target=riscv64-unknown-elf -march=rv64im -mabi=lp64 -O3 -S -ffreestanding -fno-builtin -nostdlib memmove.c
// 
// and its local labels renamed after the function, so that they do not clash with the other
// functions in the same object.
	.attribute	4, 16
	.attribute	5, "rv64i2p1_m2p0_zmmul1p0"
	.file	"memmove.c"
	.text
	.globl	memmove                         # -- Begin function memmove
	.p2align	2
	.type	memmove,@function
memmove:                                # @memmove
# %bb.0:
	beq	a0, a1, .LBBmemmove0_31
# %bb.1:
	add	a3, a2, a0
	slli	a4, a2, 1
	sub	a5, a1, a3
	neg	a4, a4
	bgeu	a4, a5, .LBBmemmove0_10
# %bb.2:
	bgeu	a0, a1, .LBBmemmove0_11
# %bb.3:
	li	a3, 16
	bltu	a2, a3, .LBBmemmove0_18
# %bb.4:
	neg	a4, a0
	andi	a4, a4, 7
	sub	a2, a2, a4
	beqz	a4, .LBBmemmove0_19
# %bb.5:
	add	a4, a1, a4
	mv	a3, a0
.LBBmemmove0_6:                                # =>This Inner Loop Header: Depth=1
	lbu	a5, 0(a1)
	addi	a1, a1, 1
	sb	a5, 0(a3)
	addi	a3, a3, 1
	bne	a1, a4, .LBBmemmove0_6
# %bb.7:
	andi	a5, a4, 7
	srli	t0, a2, 3
	beqz	a5, .LBBmemmove0_20
.LBBmemmove0_8:
	slli	a4, a5, 3
	sub	a7, a1, a5
	ld	a5, 0(a7)
	li	a6, 64
	sub	a6, a6, a4
	addi	a7, a7, 8
	slli	t0, t0, 3
	add	t0, a3, t0
	mv	t1, a3
.LBBmemmove0_9:                                # =>This Inner Loop Header: Depth=1
	srl	t2, a5, a4
	ld	a5, 0(a7)
	sll	t3, a5, a6
	or	t2, t3, t2
	sd	t2, 0(t1)
	addi	t1, t1, 8
	addi	a7, a7, 8
	bne	t1, t0, .LBBmemmove0_9
	j	.LBBmemmove0_22
.LBBmemmove0_10:
	tail	memcpy
.LBBmemmove0_11:
	li	a5, 16
	add	a4, a1, a2
	bltu	a2, a5, .LBBmemmove0_28
# %bb.12:
	andi	a5, a3, 7
	sub	a2, a2, a5
	beqz	a5, .LBBmemmove0_15
# %bb.13:
	add	a1, a1, a2
.LBBmemmove0_14:                               # =>This Inner Loop Header: Depth=1
	lbu	a5, -1(a4)
	addi	a4, a4, -1
	sb	a5, -1(a3)
	addi	a3, a3, -1
	bne	a4, a1, .LBBmemmove0_14
.LBBmemmove0_15:
	andi	a1, a4, 7
	srli	a7, a2, 3
	beqz	a1, .LBBmemmove0_25
# %bb.16:
	slli	a1, a1, 3
	andi	t0, a4, -8
	li	a5, 64
	ld	a6, 0(t0)
	sub	a5, a5, a1
	slli	t1, a7, 3
	addi	a7, a3, -8
	sub	t1, a3, t1
	addi	t0, t0, -8
	addi	t1, t1, -8
.LBBmemmove0_17:                               # =>This Inner Loop Header: Depth=1
	sll	t2, a6, a5
	ld	a6, 0(t0)
	srl	t3, a6, a1
	or	t2, t3, t2
	sd	t2, 0(a7)
	addi	a7, a7, -8
	addi	t0, t0, -8
	bne	a7, t1, .LBBmemmove0_17
	j	.LBBmemmove0_27
.LBBmemmove0_18:
	mv	a3, a0
	bnez	a2, .LBBmemmove0_23
	j	.LBBmemmove0_31
.LBBmemmove0_19:
	mv	a3, a0
	andi	a5, a1, 7
	srli	t0, a2, 3
	bnez	a5, .LBBmemmove0_8
.LBBmemmove0_20:
	slli	a4, t0, 3
	add	a4, a3, a4
	mv	a5, a1
	mv	a6, a3
.LBBmemmove0_21:                               # =>This Inner Loop Header: Depth=1
	ld	a7, 0(a5)
	sd	a7, 0(a6)
	addi	a6, a6, 8
	addi	a5, a5, 8
	bne	a6, a4, .LBBmemmove0_21
.LBBmemmove0_22:
	andi	a4, a2, -8
	add	a3, a3, a4
	add	a1, a1, a4
	andi	a2, a2, 7
	beqz	a2, .LBBmemmove0_31
.LBBmemmove0_23:
	add	a2, a1, a2
.LBBmemmove0_24:                               # =>This Inner Loop Header: Depth=1
	lbu	a4, 0(a1)
	addi	a5, a1, 1
	sb	a4, 0(a3)
	addi	a3, a3, 1
	mv	a1, a5
	bne	a5, a2, .LBBmemmove0_24
	j	.LBBmemmove0_31
.LBBmemmove0_25:
	slli	a7, a7, 3
	addi	a1, a3, -8
	sub	a6, a3, a7
	addi	a5, a4, -8
	addi	a6, a6, -8
.LBBmemmove0_26:                               # =>This Inner Loop Header: Depth=1
	ld	a7, 0(a5)
	sd	a7, 0(a1)
	addi	a1, a1, -8
	addi	a5, a5, -8
	bne	a1, a6, .LBBmemmove0_26
.LBBmemmove0_27:
	andi	a1, a2, -8
	sub	a3, a3, a1
	sub	a4, a4, a1
	andi	a2, a2, 7
.LBBmemmove0_28:
	beqz	a2, .LBBmemmove0_31
# %bb.29:
	addi	a1, a3, -1
	not	a2, a2
	addi	a4, a4, -1
	add	a3, a2, a3
.LBBmemmove0_30:                               # =>This Inner Loop Header: Depth=1
	lbu	a2, 0(a4)
	sb	a2, 0(a1)
	addi	a1, a1, -1
	addi	a4, a4, -1
	bne	a1, a3, .LBBmemmove0_30
.LBBmemmove0_31:
	ret
.Lfunc_end0memmove:
	.size	memmove, .Lfunc_end0memmove-memmove
                                        # -- End function
	.ident	"clang version 23.1.4 (https://github.com/llvm/llvm-project 7a941dfb2877a0b8cf30323fefa85ad019e0b0f5)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
