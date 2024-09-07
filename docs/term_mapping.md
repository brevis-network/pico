| R0             | SP1                          | Brevis                          | Component  |
|----------------|------------------------------|---------------------------------|------------|
| Segment        | Shard                        | Chunk / Fragment / Clip / Slice | machine    |
| Session        |                              |                                 | machine    |
| Continuation   | Sharding                     | Chunking                        | machine    |
| SegmentReceipt | ShardProof                   | (Base)ChunkProof                | machine    |
|                | StarkMachine + MachineProver | (Base)Prover                    | machine    |
|                | Verifier                     | (Base)Verifier                  | machine    |
|                | SP1Prover                    | (Brevis)Machine                 | machine    |
| Receipt        | Proof                        | (Base)Proof                     | machine    |
| prove_segment  | prove_core                   | prove_chunk                     | machine    |
| lift + join    | compress + shrink            | combine + compress              | machine    |
|                | Interaction                  | (Base)Interaction               | chip       |
|                | RiscvAir / RecursionAir      | (Base)ChipType                  | chip       |
|                | Chip                         | MetaChip                        | chip       |
|                | MachineAir                   | ChipBehavior                    | chip       |
| identity_p254  | wrap_bn254                   | embed_bn254                     | compiler   |
| stark_to_snark | wrap_plonk_bn254             | convert_groth16                 | compiler   |
|                | Program                      | (Base)Program                   | compiler   |
|                | Runtime                      | (Base)Runtime                   | compiler   |
|                | OpeningProof                 | PcsProof                        | compiler   |
|                | OpeningError                 | PcsError                        | compiler   |