# Features @ Stages

## ~~Addition~~
#### Goal
- Pico-VM should be able to prove a simple addition program in the first stage.
#### Features
- [x] `MetaChip`
  - The structure that holds the chip's behaviors, interactions, etc;
- [x] `main`
  - Main trace of chips and its involvement in the proving procedure;
- [x] `BaseProver`
  - The core prover to be called whenever a proof from a machine is needed;
- [x] `quotient`
  - Quotient polynomials and its involvement in the proving procedure;
- [x] `BaseVerifier`
  - The core verifier to be called whenever a proof from a machine needs to be verified;
  - Ongoing
- [x] `ToyChip`
  - A simple chip that only contains the addition operation;
  - Before core executor ready, could implement the trace generation on its own;
  - After core executor ready, could implement the trace generation as expected (taking `Record` as input);
- [x] `ToyMachine`
  - A simple machine that only proves the addition program;
  - This is the final target for this stage
- [x] Core `Executor`
  - [x] Migration of the core executor to the `compiler` folder;
  - [x] Integration with current `toy_machine` and `toy_prover`

## Fibonacci (Ongoing)
#### Goal
- Pico-VM should be able to prove a small Fibonacci program at this stage.
#### Features
- [x] Abstraction framework update
  - [x] machine type/behavior
  - [x] proofs type/behavior
- [x] `Compiler` separation into `Compiler` and `Executor`
- [ ] chips for Fibonacci
  - [ ] CPU (main heavy-lifting part)
  - [ ] Program
  - [ ] MemoryProgram 
  - [ ] Memory
  - [ ] AddSub 
  - [ ] Bitwise 
  - [ ] Byte
  - [ ] Lt
  - [ ] Mul
  - [ ] ShiftLeft 
  - [ ] ShiftRight
- [x] `preprocessed`
  - Preprocessed trace of chips and its involvement in the proving procedure;
  - Partially done, need to complete by adding it to the production of `ChunkProof`
- [ ] public values
- [x] dependencies 
- [x] lookups (need to be carefully handled)
  - [x] interactions
  - [x] permutation 
    - [x] traces generation
    - [x] eval

## Large Fibonacci
#### Goal
- Pico-VM should be able to prove a Fibonacci program with huge workload (thus need to be chunked) at this stage.
#### Features
- [ ] Chunking support for base machine
  - [ ] chips
  - [ ] machine
- [ ] Concrete instantiation
  - [ ] BaseMachine
  - [ ] CompressMachine
  - [ ] CombineMachine
  - [ ] EmbedMachine
  - [ ] Wrap - need to be a machine?
  - [ ] PicoMachine, not exactly a machine type but a wrapper of various machines to support own logic
- [ ] Recursion `Executor` 
  - [ ] migration
  - [ ] detach to compiler
- [ ] Executor abstraction

## Performance Optimization
#### Goal
- Pico-VM should be thuroughly profiled and optimized to perform on-par with existing system (CPU version).
#### Features
- [ ] Complete profiling
  - [ ] proof sizes
  - [ ] chip workload
  - [ ] cpu time
  - [ ] user time
- [ ] Adding parallelization
- [ ] Deferred proofs
- [ ] Precompile chips
- [ ] config extension: M31 field and CSTARK
- [ ] batch opening and verifying (mmcs)
- [ ] logup-gkr integration

## Anytime
#### Goal
- The following features could be implemented at any stage, the main goal is to make the system faster, cleaner and more modular.

#### Compiler Features
- [ ] Zirgen - circuits



