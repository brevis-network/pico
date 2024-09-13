# Design Ideas

### General
- [ ] Taking abstraction to the next level.
  - Currently, both CoreVM and RecursionVM are implemented separately (`core/` vs. `recursion/`, but they share a lot of common logic. In more details, RecursionVM actually contains multiple types for different purposes (`compress`, `shrink`, `wrap`, etc.) by implementing modularily;
  - We could consider taking the abstraction of the whole VM to the next level by constructing a BaseVM, and then implement VMs for different purposes by realizing the BaseVM components;
  - More specifically, a BaseVM should contain specific implementations of:
    1. Compiler/Runtime
    2. Chips and Airs
    3. Proving Systems

    Realization of such BaseVM will simply be realization of 1, 2, 3 for different purposes.
  - This could make the code much more modular and easy to maintain/extend.
  
- [ ] Parallelism enhancement
  - Operation-level, chip-level, shard-level parallelism check and enhancement. 

### Chips

- [ ] Loading chips for different machines in a modular way.
  - Currently, chips are hard-coded and located in the folders of the corresponding machine. Adding a new (precompile) chip is a tedious procedure;
  - With BaseVM defined, we consider offloading all chip-related implementation into a single folder where each chip is a single subfolder. Each specific VM could load a different subset of chips in the chip folder based on its special purpose;
  - Chips in this way could be more modular and easier to maintain, as opposed to current case where `Col`, `Air`, `AirBuilder`, `Event` for a single chip might be located at different places and chips are located in specific VM folder and hard to be shared.

- [ ] Let chips define `EmulationRecord` -- `EmulationRecord` should only contain events that the set of chips defining the machine could accept and used to generate trace. One should not define `ExecutionRecord` and the `ChipType` enum for a machine separately.

- [ ] Dynamic ISA
  - Following the design of modular precompile chips, we could actually implement a dynamic (subset) of full ISA to reduce prover overhead. ISA could be determined right after `runtime` is generated, and the corresponding chips could then be loaded to construct prover.
  - Verifier need to change?
  - This can actually work for both CoreVM and RecursionVM, but whether it can save on time needs second thought. If the main logic of verifier is a selector, shrinking ISA dynamically might save on time.

- [ ] Chip workload balance
  - Currently, some chips takes more workload than others and this may lead to inefficiency when invoking chip computation parallelism. One should consider offload some workload to other chips and make the workload more balanced.

### Proving Systems

- [ ] **Supporting multiple fields**
  - BabyBear
  - M31
- [ ] **Supporting multiple hashes**
  - Poseidon2
  - Blake (e.g., https://hackmd.io/@starkware-hackmd/SJUbOQj9C)
- [ ] **Supporting multiple lookup arguments**
  - GrandProduct
  - LogUp
  - LogUp-GKR
  - etc.


### Recursion
- [ ] Recursion with precomiples 
  - adding more specialized circuits (for each chip) and reduce the ISA set. Ideally, only #Chips plus a small number of extra opcodes are needed.
- [ ] Supporting heterogeneous deferred proofs
  - Currently zk-coprocessor is generating a plonky2 proof. Being able to integrate it with our own VM will enhance synergy;
  - Would be beneficial if different proof types could be combined, including GKR and other types of proofs.
  - Such heterogeneous proofs could happen at different places like lookups, precompiles, etc.
  - Possible proving systems to be integrated
    - Plonkish (plonky2)
    - CSTARK
    - GKR (uni/multi)
    - Binius
    - Others
- [ ] Multi-machine distributed proving
- [ ] Shrinking the proof size earlier in the recursion process


# Design Choices to be Discussed

- [ ] Adding `Val` to `SC`. 
  - Currently `Val<SC>` is already able to extract the field type from SC instance, thus adding its own `Val` is purely a design choice. 
  - Adding it will make development easier but the development will be riskier since it might introduce inconsistency of `Val` against other parts of `SC`. 
  - Experimental branch at `experimental/generic_chiptype` and is left for future discussion. 
- [ ] Decompose current `compiler` into `compiler` and `vm`.
  - Currently `compiler` is containing both the compilation of source code to machine code (e.g., `Rust` to `Program`) and machine code to record (e.g., `Program` to `ExecutionRecord`). 
  - Decomposing will make it easier to maintain and extend the code.
  - Meanwhile, necessity needs to be considered since if each of compiler is tightly coupled with the vm, it might be better to keep them together in one folder instead of separating them.
- [ ] `Deferred` implementation.
  * Some use cases: [https://www.youtube.com/watch?v=x0-7Y46bQO0](https://www.youtube.com/watch?v=x0-7Y46bQO0)
  * Could think of how to integrate zk-coprocessor into our VM, which may play a key role in differentiation against other existing VMs.
  * Also keep in mind it might be useful when multiple proving systems kick in.

# Detailed Code Org

- [ ] Rename `PairCol` since the current name makes little sense;
- [ ] Necessity to add `col` to each of sub chips in `core/src/alu`;
- [ ] `Program` defined in `core/src/runtime/program.rs` but implemented in `core/src/disassembler`. `disassembler` should be integrated into `runtime`;
- [ ] `Instruction` defined in `core/src/runtime/instruction.rs` but implemented in `disassembler`
- [ ] `VerifierConstraintFolder` and `GenericVerifierConstraintFolder` could be merged in `core/src/stark/folder.rs`
- [ ] `permutation` implemented in `stark/permutation.rs` but only used in `stark/chip.rs`
- [ ] `quotient_values` implemented in `stark/quotient.rs` but only used in `stark/prover.rs`
- [ ] `memory` related records are located in `core/src/runtime/memory.rs` but `MemoryAccessRecord` in `record.rs`
- [ ] `PublicValues` vs. `SP1PublicValues`, and multiple places for “normal” `public_values`
- [ ] `Events` are located in different places (`event.rs`, `mod.rs`, etc)
- [ ] `Instruction` defined in both `recursion/../runtime/instruction.rs` and `core/src/runtime/instruction.rs` , essential reason is they use different `Opcode`. Should consider rename to emphasize differences (e.g., Program is already differentiated: `Program` vs. `RecursionProgram`)
- [ ] `core/src/alu/lt/mod.rs` L\#104, `type Program = Program` necessary?
- [ ] `AirBuilder` part is messy
- [ ] `core/src/program/mod.rs`
    * tests: is it really testing anything?
    * necessity: consider merge it directly with `cpuchip` — see no reason for separating it out.
- [ ] Decouple `MemoryInitialize` and `MemoryFinalize`?
- [ ] `SP1Prover` in `prover/src/verify.rs` a bit confusing to users as it includes prover and verifier in a single
  struct, as opposed to `MachineProver` in `core/src/stark`
- [ ] `SP1ReducedProof` and `SP1ReduceProof` confusing
- [ ] `MachineProgram` abstraction really necessary? Since `Program` already has `pc_start`
- [ ] `IsExtZeroOperation` and `IsZeroOperation` in `recursion/core/src/air/` should be in `operations` folder
- [ ] `MultiTableAirBuilder` and `MultiBuilder` are confusing.
- [ ] `AirBuilder` and `Air` should be defined out of core since these are also shared with recursion chips
- [ ] Necessity for all files in `recursion/core/src/cpu/air/`? Or just implement them in one place? This is a new way of implementation of CpuChip, but it should bring lots of overhead\! Might be able to improve
- [x] Why `Block` only exist in recursion but not core? Shouldn’t it be used in both cases, or is it redundant?
- Recursion VM is handling both 32bits and 128bits (extension field), as opposed to Core VM where only 32bits are handled.
- [ ] `CpuChip` same name redefined in recursion. Should specify a new name.
- [ ] `Poseidon2CompressEvent` and `Poseidon2HashEvent` both in `EmulationRecord`?
- [ ] `EmulationRecord` in recursion should be renamed
