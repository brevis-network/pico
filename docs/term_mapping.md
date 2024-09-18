| R0             | SP1                                          | Brevis                         |
|----------------|----------------------------------------------|--------------------------------|
| Segment        | Shard                                        | Element                        | 
| Session        |                                              | Ensemble                       | 
| SegmentReceipt | ShardProof                                   | BaseProof                      | 
|                | MachineProof                                 | EnsembleProof                  | 
|                | StarkMachine + MachineProver                 | BaseProver                     | 
|                | Verifier                                     | BaseVerifier                   | 
|                | SP1Prover                                    | (Pico)Machine                  | 
| prove_segment  | core                                         | riscv                          |
| lift + join    | compress + shrink                            | combine + compress             | 
|                | SymbolicLookup                               | SymbolicLookup                 | 
|                | Interaction                                  | VirtualPairLookup              | 
|                | send                                         | looking                        | 
|                | receive                                      | looked                         | 
|                | InteractionBuilder + SymbolicAirBuilder      | SymbolicConstraintFolder       | 
|                | MessageBuilder                               | LookupBuilder                  | 
|                | Message                                      | Lookup                         | 
|                | PermutaiontAirBuilder + MultiTableAirBuilder | PermutationBuilder             | 
|                | BaseAirBuilder + PairBuilder                 | ChipBuilder                    | 
|                | RiscvAir / RecursionAir                      | ChipType                       | 
|                | Chip                                         | MetaChip                       | 
|                | MachineAir                                   | ChipBehavior                   | 
| identity_p254  | wrap_bn254                                   | embed_bn254                    | 
| stark_to_snark | wrap_plonk_bn254                             | convert_groth16                | 
|                | Program                                      | Program                        | 
|                | Emulator                                     | Emulator                       | 
|                | MachineRecord                                | RecordBehavior                 |
|                | OpeningProof                                 | PcsProof                       | 
|                | OpeningError                                 | PcsError                       | 
|                | generate_dependencies                        | extra_record/complement_record |