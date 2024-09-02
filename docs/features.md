# Features @ Stages

## Addition
#### Goal
- Pico-VM should be able to prove a simple addition program in the first stage.
#### Features
- [x] `BaseChip`
  - The structure that holds the chip's behaviors, interactions, etc;
- [x] `main`
  - Main trace of chips and its involvement in the proving procedure;
- [x] `BaseProver`
  - The core prover to be called whenever a proof from a machine is needed;
- [x] `quotient`
  - Quotient polynomials and its involvement in the proving procedure;
- [ ] `BaseVerifier`
  - The core verifier to be called whenever a proof from a machine needs to be verified;
  - Ongoing
- [ ] `Executor` migration for core
  - Migration of the core executor to the `compiler` folder;
  - Need to be able to compile a simple `addition` code;
- [ ] `ToyChip`
  - A simple chip that only contains the addition operation;
  - Before core executor ready, could implement the trace generation on its own;
  - After core executor ready, could implement the trace generation as expected (taking `Record` as input);
- [ ] `ToyMachine`
  - A simple machine that only proves the addition program;
  - This is the final target for this stage

## Fibonacci
#### Goal
- Pico-VM should be able to prove a small Fibonacci program in this stage.
#### Features
- [ ] chips for Fibonacci
  - [ ] CPU (main heavy-lifting part)
  - [ ] Program
  - [ ] MemoryProgram 
  - [ ] AddSub 
  - [ ] Bitwise 
  - [ ] Byte
  - [ ] Lt
  - [ ] Mul
  - [ ] ShiftLeft 
  - [ ] ShiftRight
- [ ] `preprocessed`
  - Preprocessed trace of chips and its involvement in the proving procedure;
  - Partially done, need to complete by adding it to the production of `ChunkProof`
- [ ] public values
- [ ] chip ordering
- [ ] dependencies 
- [ ] lookups (need to be carefully handled)
  - [ ] interactions
  - [ ] permutation 
    - [ ] traces
    - [ ] eval

## Large fibonacci
#### Goal
- Pico-VM should be able to prove a Fibonacci program with huge workload (thus need to be chunked) in this stage.
#### Features
- [ ] chunking
  - [ ] baseprover
  - [ ] baseverifier
  - [ ] proofs
- [ ] recursion executor migration
- [ ] compiler detach

## Anytime
#### Goal
- The following features could be implemented at any stage, the main goal is to make the system faster, cleaner and more modular.

#### Compiler Features
- [ ] Zirgen - circuits

#### Prover Features
- [ ] batch opening and verifying (mmcs)
- [ ] multiple fields/starks
- [ ] logup-gkr
- [ ] deferred proofs

#### Others
- [ ] Parallelism
