use crate::Error;
use cudart_sys::*;
use std::ffi::c_void;

unsafe extern "C" {
    pub fn cuda_byte_generate_preprocessed(
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_riscv_poseidon2_generate_main(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        d_dummy_row: *const c_void,
        d_round_constants: *const c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_riscv_program_generate_preprocessed_u64(
        d_instrs: *const c_void,
        num_instrs: usize,
        padded_num_rows: usize,
        pc_base: u64,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_riscv_program_generate_main_u64(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        pc_base: u64,
        d_events: *const c_void,
        d_trace: *mut c_void,
        stream: cudaStream_t,
        num_instrs: usize,
    ) -> Error;

    pub fn cuda_weierstrass_add_secp256k1_generate_extra_record_and_main(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_weierstrass_add_secp256r1_generate_extra_record_and_main(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_weierstrass_add_bn254_generate_extra_record_and_main(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_weierstrass_add_bls12381_generate_extra_record_and_main(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_weierstrass_double_secp256k1_generate_extra_record_and_main(
        d_events: *const c_void,
        num_events: usize,
        d_trace: *mut c_void,
        num_rows: usize,
        num_cols: usize,
        byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_weierstrass_double_secp256r1_generate_extra_record_and_main(
        d_events: *const c_void,
        num_events: usize,
        d_trace: *mut c_void,
        num_rows: usize,
        num_cols: usize,
        byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_weierstrass_double_bn254_generate_extra_record_and_main(
        d_events: *const c_void,
        num_events: usize,
        d_trace: *mut c_void,
        num_rows: usize,
        num_cols: usize,
        byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_weierstrass_double_bls12381_generate_extra_record_and_main(
        d_events: *const c_void,
        num_events: usize,
        d_trace: *mut c_void,
        num_rows: usize,
        num_cols: usize,
        byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_weierstrass_decompress_bls12381_generate_extra_record_and_main(
        d_events: *const c_void,
        num_events: usize,
        d_trace: *mut c_void,
        num_rows: usize,
        num_cols: usize,
        num_lexi_cols: usize,
        lexi: bool,
        byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_weierstrass_decompress_secp256k1_generate_extra_record_and_main(
        d_events: *const c_void,
        num_events: usize,
        d_trace: *mut c_void,
        num_rows: usize,
        num_cols: usize,
        num_lexi_cols: usize,
        lexi: bool,
        byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_weierstrass_decompress_secp256r1_generate_extra_record_and_main(
        d_events: *const c_void,
        num_events: usize,
        d_trace: *mut c_void,
        num_rows: usize,
        num_cols: usize,
        num_lexi_cols: usize,
        lexi: bool,
        byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_edwards_add_ed25519_generate_extra_record_and_main(
        d_events: *const c_void,
        num_events: usize,
        d_trace: *mut c_void,
        num_rows: usize,
        num_cols: usize,
        byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_edwards_decompress_generate_extra_record_and_main(
        d_events: *const c_void,
        num_events: usize,
        d_trace: *mut c_void,
        num_rows: usize,
        num_cols: usize,
        byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_alu_base_generate_preprocessed(
        d_events: *const c_void,
        event_size: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_alu_base_generate_main(
        d_events: *const c_void,
        event_size: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_alu_ext_generate_preprocessed(
        d_events: *const c_void,
        event_size: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_alu_ext_generate_main(
        d_events: *const c_void,
        event_size: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_assert_zero_ext_generate_preprocessed(
        d_instrs: *const c_void,
        num_instrs: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_assert_zero_ext_generate_main(
        d_events: *const c_void,
        event_size: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_mle_open_generate_preprocessed(
        d_instrs: *const c_void,
        num_instrs: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_mle_open_generate_main(
        d_events: *const c_void,
        event_size: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_frac_fold_generate_preprocessed(
        d_instrs: *const c_void,
        num_instrs: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_frac_fold_generate_main(
        d_events: *const c_void,
        event_size: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_univariate_fold_generate_preprocessed(
        d_instrs: *const c_void,
        num_instrs: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_univariate_fold_generate_main(
        d_events: *const c_void,
        event_size: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        w: u32,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_unpack_block_generate_preprocessed(
        d_instrs: *const c_void,
        num_instrs: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_unpack_block_generate_main(
        d_events: *const c_void,
        event_size: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_lagrange_eval_d2_generate_preprocessed(
        d_instrs: *const c_void,
        num_instrs: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_lagrange_eval_d2_generate_main(
        d_events: *const c_void,
        event_size: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_pack_block_generate_preprocessed(
        d_instrs: *const c_void,
        num_instrs: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_pack_block_generate_main(
        d_events: *const c_void,
        event_size: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_digest_select_generate_preprocessed(
        d_instrs: *const c_void,
        num_instrs: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_digest_select_generate_main(
        d_events: *const c_void,
        event_size: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_ext_dot_product_generate_preprocessed(
        d_metas: *const c_void,
        num_instrs: usize,
        d_mu_addrs_flat: *const c_void,
        d_val_addrs_flat: *const c_void,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_ext_dot_product_generate_main(
        d_events: *const c_void,
        event_size: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_gkr_sumcheck_round_generate_preprocessed(
        d_instrs: *const c_void,
        num_instrs: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_gkr_sumcheck_round_generate_main(
        d_events: *const c_void,
        event_size: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        w: u32,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_horner_eval_generate_preprocessed(
        d_metas: *const c_void,
        num_instrs: usize,
        d_coeff_addrs_flat: *const c_void,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_horner_eval_generate_main(
        d_events: *const c_void,
        event_size: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        w: u32,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_binary_fold_step_generate_preprocessed(
        d_instrs: *const c_void,
        num_instrs: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_binary_fold_step_generate_main(
        d_events: *const c_void,
        event_size: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        inv2: u32,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_poseidon2_packed_generate_preprocessed(
        d_instrs: *const c_void,
        num_instrs: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_exp_bits_len_generate_preprocessed(
        d_metas: *const c_void,
        num_instrs: usize,
        d_bit_outs_flat: *const c_void,
        d_trace: *mut c_void,
        num_cols: usize,
        num_real_rows: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_exp_bits_len_generate_main(
        d_events: *const c_void,
        num_events: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        num_rows: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_select_generate_preprocessed(
        d_events: *const c_void,
        event_size: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_select_generate_main(
        d_events: *const c_void,
        event_size: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_public_values_generate_preprocessed(
        d_events: *const c_void,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_public_values_generate_main(
        d_events: *const c_void,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_exp_bits_generate_preprocessed(
        d_events: *const c_void,
        event_size: usize,
        d_bits: *const c_void,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_exp_bits_generate_main(
        d_events: *const c_void,
        event_size: usize,
        d_bits: *const c_void,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_batch_fri_generate_preprocessed(
        d_instrs: *const c_void,
        instrs_size: usize,
        d_p_at_x: *const c_void,
        d_p_at_z: *const c_void,
        d_alpha_pow: *const c_void,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_batch_fri_generate_main(
        d_events: *const c_void,
        event_size: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_recursion_mem_const_generate_preprocessed(
        d_events: *const c_void,
        event_size: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_recursion_mem_var_generate_preprocessed(
        d_events: *const c_void,
        event_size: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_recursion_mem_var_generate_main(
        d_events: *const c_void,
        event_size: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_recursion_poseidon2_generate_preprocessed(
        d_instrs: *const c_void,
        num_instrs: usize,
        d_trace: *mut c_void,
        num_cols: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_recursion_poseidon2_generate_main(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        d_dummy_row: *const c_void,
        d_round_constants: *const c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_extra_record_initialize_byte_trace(
        d_byte_trace: *mut c_void,
        byte_trace_size: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_extra_record_finalize_byte_trace(
        d_byte_trace: *mut c_void,
        byte_trace_size: usize,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_add_generate_extra_record_and_main(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_addw_generate_extra_record_and_main(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_sub_generate_extra_record_and_main(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_subw_generate_extra_record_and_main(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_bitwise_generate_extra_record_and_main_u64(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_divrem_generate_extra_record_and_main(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        stream: cudaStream_t,
        d_extra_event_indices: *const c_void,
        d_byte_trace: *mut c_void,
        d_alu_add_sub_events: *mut c_void,
        alu_add_sub_events_start_index: usize,
    ) -> Error;

    pub fn cuda_lt_generate_extra_record_and_main_u64(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_mul_generate_extra_record_and_main_u64(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_sll_generate_extra_record_and_main_u64(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_sr_generate_extra_record_and_main_u64(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_cpu_generate_extra_record_and_main_u64(
        num_cols: usize,
        event_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        stream: cudaStream_t,
        d_extra_event_indices: *const c_void,
        d_byte_trace: *mut c_void,
        d_alu_add_sub_events: *mut c_void,
        alu_add_sub_events_start_index: usize,
        d_alu_lt_events: *mut c_void,
        alu_lt_events_start_index: usize,
    ) -> Error;

    pub fn cuda_cpu_pad_trace_u64(
        num_cols: usize,
        start_row: usize,
        end_row: usize,
        d_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_riscv_global_generate_extra_record_and_main(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        stream: cudaStream_t,
        d_byte_trace: *mut c_void,
        d_poseidon2_events: *mut c_void,
        poseidon2_events_start_index: usize,
        d_round_constants: *const c_void,
    ) -> Error;

    pub fn cuda_memory_initialize_finalize_generate_extra_record_and_main_u64(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_previous_addr_limbs: *const c_void,
        d_trace: *mut c_void,
        d_global_events: *mut c_void,
        global_events_start_index: usize,
        is_receive: bool,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_memory_local_generate_extra_record_and_main_u64(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        stream: cudaStream_t,
        d_global_events: *mut c_void,
        global_events_start_index: usize,
        d_byte_trace: *mut c_void,
    ) -> Error;

    pub fn cuda_memory_read_write_generate_extra_record_and_main_u64(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_event_indices: *const c_void,
        d_trace: *mut c_void,
        stream: cudaStream_t,
        d_byte_trace: *mut c_void,
    ) -> Error;

    pub fn cuda_syscall_generate_extra_record_and_main_u64(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        stream: cudaStream_t,
        d_global_events: *mut c_void,
        global_events_start_index: usize,
        // Matches `enum class SyscallChunkKind : uint8_t` on the device side. Declaring this
        // usize made the two sides disagree on the parameter's width.
        chunk_kind: u8,
        d_byte_trace: *mut c_void,
    ) -> Error;

    pub fn cuda_ecall_generate_extra_record_and_main_u64(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        stream: cudaStream_t,
        d_byte_trace: *mut c_void,
    ) -> Error;

    pub fn cuda_precompile_poseidon2_generate_extra_record_and_main(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        d_dummy_row: *const c_void,
        d_round_constants: *const c_void,
        stream: cudaStream_t,
        d_byte_trace: *mut c_void,
    ) -> Error;

    pub fn cuda_precompile_keccak_generate_extra_record_and_main(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_precompile_keccak_control_generate_extra_record_and_main(
        d_events: *const c_void,
        events_len: usize,
        d_trace: *mut c_void,
        total_rows: usize,
        num_cols: usize,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_precompile_uint256_generate_extra_record_and_main(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_precompile_sha256_compress_generate_extra_record_and_main(
        d_events: *const c_void,
        events_len: usize,
        event_size: usize,
        d_trace: *mut c_void,
        total_rows: usize,
        num_cols: usize,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_precompile_sha256_compress_control_generate_extra_record_and_main(
        d_events: *const c_void,
        events_len: usize,
        d_trace: *mut c_void,
        total_rows: usize,
        num_cols: usize,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_precompile_sha256_extend_generate_extra_record_and_main(
        d_events: *const c_void,
        events_len: usize,
        d_trace: *mut c_void,
        total_rows: usize,
        num_cols: usize,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_precompile_sha256_extend_control_generate_extra_record_and_main(
        d_events: *const c_void,
        events_len: usize,
        d_trace: *mut c_void,
        total_rows: usize,
        num_cols: usize,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_precompile_fp2_add_sub_bn254_generate_extra_record_and_main(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_precompile_fp2_add_sub_bls12381_generate_extra_record_and_main(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_precompile_fp2_mul_bn254_generate_extra_record_and_main(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_precompile_fp2_mul_bls12381_generate_extra_record_and_main(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_precompile_fp_op_bls381_generate_extra_record_and_main(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        d_dummy_row: *const c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_precompile_fp_op_bn254_generate_extra_record_and_main(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        d_dummy_row: *const c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_precompile_fp_op_secp256k1_generate_extra_record_and_main(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        d_dummy_row: *const c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    pub fn cuda_alu_partition_events(
        all_events: *const c_void,
        total_count: usize,
        out_add: *mut c_void,
        out_sub: *mut c_void,
        out_addw: *mut c_void,
        out_subw: *mut c_void,
        stream: cudaStream_t,
    ) -> Error;

    // ─── Packed-event (MLE_PACKED_EVENTS=1) entries; format_version must be
    // PACKED_EVENT_FORMAT_V1 or the CUDA side returns an error (loud unpaired-deploy guard). ───

    pub fn cuda_cpu_generate_extra_record_and_main_u64_packed(
        num_cols: usize,
        event_size: usize,
        d_events: *const c_void,
        chunk: usize,
        d_trace: *mut c_void,
        stream: cudaStream_t,
        d_extra_event_indices: *const c_void,
        d_byte_trace: *mut c_void,
        d_alu_add_sub_events: *mut c_void,
        alu_add_sub_events_start_index: usize,
        d_alu_lt_events: *mut c_void,
        alu_lt_events_start_index: usize,
        format_version: usize,
    ) -> Error;

    pub fn cuda_memory_read_write_generate_extra_record_and_main_u64_packed(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_mem_records: *const c_void,
        chunk: usize,
        d_event_indices: *const c_void,
        d_trace: *mut c_void,
        stream: cudaStream_t,
        d_byte_trace: *mut c_void,
        format_version: usize,
    ) -> Error;

    pub fn cuda_ecall_generate_extra_record_and_main_u64_packed(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        chunk: usize,
        d_trace: *mut c_void,
        stream: cudaStream_t,
        d_byte_trace: *mut c_void,
        format_version: usize,
    ) -> Error;

    pub fn cuda_lt_generate_extra_record_and_main_u64_packed(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
        format_version: usize,
    ) -> Error;

    pub fn cuda_add_generate_extra_record_and_main_packed(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
        format_version: usize,
    ) -> Error;

    pub fn cuda_addw_generate_extra_record_and_main_packed(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
        format_version: usize,
    ) -> Error;

    pub fn cuda_sub_generate_extra_record_and_main_packed(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
        format_version: usize,
    ) -> Error;

    pub fn cuda_subw_generate_extra_record_and_main_packed(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        d_byte_trace: *mut c_void,
        stream: cudaStream_t,
        format_version: usize,
    ) -> Error;

    pub fn cuda_divrem_generate_extra_record_and_main_packed(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        d_events: *const c_void,
        d_trace: *mut c_void,
        stream: cudaStream_t,
        d_extra_event_indices: *const c_void,
        d_byte_trace: *mut c_void,
        d_alu_add_sub_events: *mut c_void,
        alu_add_sub_events_start_index: usize,
        format_version: usize,
    ) -> Error;

    pub fn cuda_riscv_program_generate_main_u64_packed(
        num_cols: usize,
        event_size: usize,
        trace_size: usize,
        pc_base: u64,
        d_events: *const c_void,
        d_trace: *mut c_void,
        stream: cudaStream_t,
        num_instrs: usize,
        format_version: usize,
    ) -> Error;

    pub fn cuda_alu_partition_events_packed(
        all_events: *const c_void,
        total_count: usize,
        out_add: *mut c_void,
        out_sub: *mut c_void,
        out_addw: *mut c_void,
        out_subw: *mut c_void,
        stream: cudaStream_t,
        format_version: usize,
    ) -> Error;
}
