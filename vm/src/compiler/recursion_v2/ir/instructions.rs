use super::{Array, Ext, Felt, MemIndex, Ptr, TracedVec, Usize, Var};
use crate::{
    configs::config::FieldGenericConfig, machine::septic::SepticCurve,
    recursion_v2::air::RecursionPublicValues,
};

/// An intermeddiate instruction set for implementing programs.
///
/// Programs written in the DSL can compile both to the recursive zkVM and the R1CS or Plonk-ish
/// circuits.
#[derive(Debug, Clone)]
#[allow(clippy::type_complexity)]
pub enum DslIr<FC: FieldGenericConfig> {
    // Immediates.
    /// Assigns an immediate to a variable (var = imm).
    ImmV(Var<FC::N>, FC::N),
    /// Assigns a field immediate to a field element (felt = field imm).
    ImmF(Felt<FC::F>, FC::F),
    /// Assigns an ext field immediate to an extension field element (ext = ext field imm).
    ImmE(Ext<FC::F, FC::EF>, FC::EF),

    // Additions.
    /// Add two variables (var = var + var).
    AddV(Var<FC::N>, Var<FC::N>, Var<FC::N>),
    /// Add a variable and an immediate (var = var + imm).
    AddVI(Var<FC::N>, Var<FC::N>, FC::N),
    /// Add two field elements (felt = felt + felt).
    AddF(Felt<FC::F>, Felt<FC::F>, Felt<FC::F>),
    /// Add a field element and a field immediate (felt = felt + field imm).
    AddFI(Felt<FC::F>, Felt<FC::F>, FC::F),
    /// Add two extension field elements (ext = ext + ext).
    AddE(Ext<FC::F, FC::EF>, Ext<FC::F, FC::EF>, Ext<FC::F, FC::EF>),
    /// Add an extension field element and an ext field immediate (ext = ext + ext field imm).
    AddEI(Ext<FC::F, FC::EF>, Ext<FC::F, FC::EF>, FC::EF),
    /// Add an extension field element and a field element (ext = ext + felt).
    AddEF(Ext<FC::F, FC::EF>, Ext<FC::F, FC::EF>, Felt<FC::F>),
    /// Add an extension field element and a field immediate (ext = ext + field imm).
    AddEFI(Ext<FC::F, FC::EF>, Ext<FC::F, FC::EF>, FC::F),
    /// Add a field element and an ext field immediate (ext = felt + ext field imm).
    AddEFFI(Ext<FC::F, FC::EF>, Felt<FC::F>, FC::EF),

    // Subtractions.
    /// Subtracts two variables (var = var - var).
    SubV(Var<FC::N>, Var<FC::N>, Var<FC::N>),
    /// Subtracts a variable and an immediate (var = var - imm).
    SubVI(Var<FC::N>, Var<FC::N>, FC::N),
    /// Subtracts an immediate and a variable (var = imm - var).
    SubVIN(Var<FC::N>, FC::N, Var<FC::N>),
    /// Subtracts two field elements (felt = felt - felt).
    SubF(Felt<FC::F>, Felt<FC::F>, Felt<FC::F>),
    /// Subtracts a field element and a field immediate (felt = felt - field imm).
    SubFI(Felt<FC::F>, Felt<FC::F>, FC::F),
    /// Subtracts a field immediate and a field element (felt = field imm - felt).
    SubFIN(Felt<FC::F>, FC::F, Felt<FC::F>),
    /// Subtracts two extension field elements (ext = ext - ext).
    SubE(Ext<FC::F, FC::EF>, Ext<FC::F, FC::EF>, Ext<FC::F, FC::EF>),
    /// Subtrancts an extension field element and an extension field immediate (ext = ext - ext
    /// field imm).
    SubEI(Ext<FC::F, FC::EF>, Ext<FC::F, FC::EF>, FC::EF),
    /// Subtracts an extension field immediate and an extension field element (ext = ext field imm
    /// - ext).
    SubEIN(Ext<FC::F, FC::EF>, FC::EF, Ext<FC::F, FC::EF>),
    /// Subtracts an extension field element and a field immediate (ext = ext - field imm).
    SubEFI(Ext<FC::F, FC::EF>, Ext<FC::F, FC::EF>, FC::F),
    /// Subtracts an extension field element and a field element (ext = ext - felt).
    SubEF(Ext<FC::F, FC::EF>, Ext<FC::F, FC::EF>, Felt<FC::F>),

    // Multiplications.
    /// Multiplies two variables (var = var * var).
    MulV(Var<FC::N>, Var<FC::N>, Var<FC::N>),
    /// Multiplies a variable and an immediate (var = var * imm).
    MulVI(Var<FC::N>, Var<FC::N>, FC::N),
    /// Multiplies two field elements (felt = felt * felt).
    MulF(Felt<FC::F>, Felt<FC::F>, Felt<FC::F>),
    /// Multiplies a field element and a field immediate (felt = felt * field imm).
    MulFI(Felt<FC::F>, Felt<FC::F>, FC::F),
    /// Multiplies two extension field elements (ext = ext * ext).
    MulE(Ext<FC::F, FC::EF>, Ext<FC::F, FC::EF>, Ext<FC::F, FC::EF>),
    /// Multiplies an extension field element and an extension field immediate (ext = ext * ext
    /// field imm).
    MulEI(Ext<FC::F, FC::EF>, Ext<FC::F, FC::EF>, FC::EF),
    /// Multiplies an extension field element and a field immediate (ext = ext * field imm).
    MulEFI(Ext<FC::F, FC::EF>, Ext<FC::F, FC::EF>, FC::F),
    /// Multiplies an extension field element and a field element (ext = ext * felt).
    MulEF(Ext<FC::F, FC::EF>, Ext<FC::F, FC::EF>, Felt<FC::F>),

    // Divisions.
    /// Divides two variables (var = var / var).
    DivF(Felt<FC::F>, Felt<FC::F>, Felt<FC::F>),
    /// Divides a field element and a field immediate (felt = felt / field imm).
    DivFI(Felt<FC::F>, Felt<FC::F>, FC::F),
    /// Divides a field immediate and a field element (felt = field imm / felt).
    DivFIN(Felt<FC::F>, FC::F, Felt<FC::F>),
    /// Divides two extension field elements (ext = ext / ext).
    DivE(Ext<FC::F, FC::EF>, Ext<FC::F, FC::EF>, Ext<FC::F, FC::EF>),
    /// Divides an extension field element and an extension field immediate (ext = ext / ext field
    /// imm).
    DivEI(Ext<FC::F, FC::EF>, Ext<FC::F, FC::EF>, FC::EF),
    /// Divides and extension field immediate and an extension field element (ext = ext field imm /
    /// ext).
    DivEIN(Ext<FC::F, FC::EF>, FC::EF, Ext<FC::F, FC::EF>),
    /// Divides an extension field element and a field immediate (ext = ext / field imm).
    DivEFI(Ext<FC::F, FC::EF>, Ext<FC::F, FC::EF>, FC::F),
    /// Divides a field immediate and an extension field element (ext = field imm / ext).
    DivEFIN(Ext<FC::F, FC::EF>, FC::F, Ext<FC::F, FC::EF>),
    /// Divides an extension field element and a field element (ext = ext / felt).
    DivEF(Ext<FC::F, FC::EF>, Ext<FC::F, FC::EF>, Felt<FC::F>),

    // Negations.
    /// Negates a variable (var = -var).
    NegV(Var<FC::N>, Var<FC::N>),
    /// Negates a field element (felt = -felt).
    NegF(Felt<FC::F>, Felt<FC::F>),
    /// Negates an extension field element (ext = -ext).
    NegE(Ext<FC::F, FC::EF>, Ext<FC::F, FC::EF>),
    /// Inverts a variable (var = 1 / var).
    InvV(Var<FC::N>, Var<FC::N>),
    /// Inverts a field element (felt = 1 / felt).
    InvF(Felt<FC::F>, Felt<FC::F>),
    /// Inverts an extension field element (ext = 1 / ext).
    InvE(Ext<FC::F, FC::EF>, Ext<FC::F, FC::EF>),

    // Control flow.
    /// Executes a for loop with the parameters (start step value, end step value, step size, step
    /// variable, body).
    For(
        Box<(
            Usize<FC::N>,
            Usize<FC::N>,
            FC::N,
            Var<FC::N>,
            TracedVec<DslIr<FC>>,
        )>,
    ),
    /// Executes an equal conditional branch with the parameters (lhs var, rhs var, then body, else
    /// body).
    IfEq(
        Box<(
            Var<FC::N>,
            Var<FC::N>,
            TracedVec<DslIr<FC>>,
            TracedVec<DslIr<FC>>,
        )>,
    ),
    /// Executes a not equal conditional branch with the parameters (lhs var, rhs var, then body,
    /// else body).
    IfNe(
        Box<(
            Var<FC::N>,
            Var<FC::N>,
            TracedVec<DslIr<FC>>,
            TracedVec<DslIr<FC>>,
        )>,
    ),
    /// Executes an equal conditional branch with the parameters (lhs var, rhs imm, then body, else
    /// body).
    IfEqI(
        Box<(
            Var<FC::N>,
            FC::N,
            TracedVec<DslIr<FC>>,
            TracedVec<DslIr<FC>>,
        )>,
    ),
    /// Executes a not equal conditional branch with the parameters (lhs var, rhs imm, then body,
    /// else body).
    IfNeI(
        Box<(
            Var<FC::N>,
            FC::N,
            TracedVec<DslIr<FC>>,
            TracedVec<DslIr<FC>>,
        )>,
    ),
    /// Break out of a for loop.
    Break,

    // Assertions.
    /// Assert that two variables are equal (var == var).
    AssertEqV(Var<FC::N>, Var<FC::N>),
    /// Assert that two variables are not equal (var != var).
    AssertNeV(Var<FC::N>, Var<FC::N>),
    /// Assert that two field elements are equal (felt == felt).
    AssertEqF(Felt<FC::F>, Felt<FC::F>),
    /// Assert that two field elements are not equal (felt != felt).
    AssertNeF(Felt<FC::F>, Felt<FC::F>),
    /// Assert that two extension field elements are equal (ext == ext).
    AssertEqE(Ext<FC::F, FC::EF>, Ext<FC::F, FC::EF>),
    /// Assert that two extension field elements are not equal (ext != ext).
    AssertNeE(Ext<FC::F, FC::EF>, Ext<FC::F, FC::EF>),
    /// Assert that a variable is equal to an immediate (var == imm).
    AssertEqVI(Var<FC::N>, FC::N),
    /// Assert that a variable is not equal to an immediate (var != imm).
    AssertNeVI(Var<FC::N>, FC::N),
    /// Assert that a field element is equal to a field immediate (felt == field imm).
    AssertEqFI(Felt<FC::F>, FC::F),
    /// Assert that a field element is not equal to a field immediate (felt != field imm).
    AssertNeFI(Felt<FC::F>, FC::F),
    /// Assert that an extension field element is equal to an extension field immediate (ext == ext
    /// field imm).
    AssertEqEI(Ext<FC::F, FC::EF>, FC::EF),
    /// Assert that an extension field element is not equal to an extension field immediate (ext !=
    /// ext field imm).
    AssertNeEI(Ext<FC::F, FC::EF>, FC::EF),

    // Memory instructions.
    /// Allocate (ptr, len, size) a memory slice of length len
    Alloc(Ptr<FC::N>, Usize<FC::N>, usize),
    /// Load variable (var, ptr, index)
    LoadV(Var<FC::N>, Ptr<FC::N>, MemIndex<FC::N>),
    /// Load field element (var, ptr, index)
    LoadF(Felt<FC::F>, Ptr<FC::N>, MemIndex<FC::N>),
    /// Load extension field
    LoadE(Ext<FC::F, FC::EF>, Ptr<FC::N>, MemIndex<FC::N>),
    /// Store variable at address
    StoreV(Var<FC::N>, Ptr<FC::N>, MemIndex<FC::N>),
    /// Store field element at address
    StoreF(Felt<FC::F>, Ptr<FC::N>, MemIndex<FC::N>),
    /// Store extension field at address
    StoreE(Ext<FC::F, FC::EF>, Ptr<FC::N>, MemIndex<FC::N>),

    /// Force reduction of field elements in circuit.
    ReduceE(Ext<FC::F, FC::EF>),

    // Bits.
    /// Decompose a variable into size bits (bits = num2bits(var, size)). Should only be used when
    /// target is a gnark circuit.
    CircuitNum2BitsV(Var<FC::N>, usize, Vec<Var<FC::N>>),
    /// Decompose a field element into bits (bits = num2bits(felt)). Should only be used when
    /// target is a gnark circuit.
    CircuitNum2BitsF(Felt<FC::F>, Vec<Var<FC::N>>),
    /// Convert a Felt to a Var in a circuit. Avoids decomposing to bits and then reconstructing.
    CircuitFelt2Var(Felt<FC::F>, Var<FC::N>),

    // Hashing.
    /// Permutes an array of baby bear elements using Poseidon2 (output = p2_permute(array)).
    Poseidon2PermuteBabyBear(Box<(Array<FC, Felt<FC::F>>, Array<FC, Felt<FC::F>>)>),
    /// Compresses two baby bear element arrays using Poseidon2 (output = p2_compress(array1,
    /// array2)).
    Poseidon2CompressBabyBear(
        Box<(
            Array<FC, Felt<FC::F>>,
            Array<FC, Felt<FC::F>>,
            Array<FC, Felt<FC::F>>,
        )>,
    ),
    /// Absorb an array of baby bear elements for a specified hash instance.
    Poseidon2AbsorbBabyBear(Var<FC::N>, Array<FC, Felt<FC::F>>),
    /// Finalize and return the hash digest of a specified hash instance.
    Poseidon2FinalizeBabyBear(Var<FC::N>, Array<FC, Felt<FC::F>>),
    /// Permutes an array of baby bear elements using Poseidon2 (output = p2_permute(array)).
    Poseidon2PermuteKoalaBear(Box<(Array<FC, Felt<FC::F>>, Array<FC, Felt<FC::F>>)>),
    /// Compresses two koala bear element arrays using Poseidon2 (output = p2_compress(array1,
    /// array2)).
    Poseidon2CompressKoalaBear(
        Box<(
            Array<FC, Felt<FC::F>>,
            Array<FC, Felt<FC::F>>,
            Array<FC, Felt<FC::F>>,
        )>,
    ),
    /// Absorb an array of koala bear elements for a specified hash instance.
    Poseidon2AbsorbKoalaBear(Var<FC::N>, Array<FC, Felt<FC::F>>),
    /// Finalize and return the hash digest of a specified hash instance.
    Poseidon2FinalizeKoalaBear(Var<FC::N>, Array<FC, Felt<FC::F>>),
    /// Permutes an array of Bn254 elements using Poseidon2 (output = p2_permute(array)). Should
    /// only be used when target is a gnark circuit.
    CircuitPoseidon2Permute([Var<FC::N>; 3]),
    /// Permutates an array of BabyBear elements in the circuit.
    CircuitPoseidon2PermuteBabyBear(Box<[Felt<FC::F>; 16]>),
    /// Permutates an array of BabyBear elements in the circuit using the skinny precompile.
    CircuitV2Poseidon2PermuteBabyBear(Box<([Felt<FC::F>; 16], [Felt<FC::F>; 16])>),
    /// Permutates an array of KoalaBear elements in the circuit.
    CircuitPoseidon2PermuteKoalaBear(Box<[Felt<FC::F>; 16]>),
    /// Permutates an array of KoalaBear elements in the circuit using the skinny precompile.
    CircuitV2Poseidon2PermuteKoalaBear(Box<([Felt<FC::F>; 16], [Felt<FC::F>; 16])>),
    /// Commits the public values.
    CircuitV2CommitPublicValues(Box<RecursionPublicValues<Felt<FC::F>>>),

    // Miscellaneous instructions.
    /// Decompose hint operation of a usize into an array. (output = num2bits(usize)).
    HintBitsU(Array<FC, Var<FC::N>>, Usize<FC::N>),
    /// Decompose hint operation of a variable into an array. (output = num2bits(var)).
    HintBitsV(Array<FC, Var<FC::N>>, Var<FC::N>),
    /// Decompose hint operation of a field element into an array. (output = num2bits(felt)).
    HintBitsF(Array<FC, Var<FC::N>>, Felt<FC::F>),
    /// Decompose hint operation of a field element into an array. (output = num2bits(felt)).
    CircuitV2HintBitsF(Vec<Felt<FC::F>>, Felt<FC::F>),
    /// Prints a variable.
    PrintV(Var<FC::N>),
    /// Prints a field element.
    PrintF(Felt<FC::F>),
    /// Prints an extension field element.
    PrintE(Ext<FC::F, FC::EF>),
    /// Throws an error.
    Error(),

    /// Converts an ext to a slice of felts.  
    HintExt2Felt(Array<FC, Felt<FC::F>>, Ext<FC::F, FC::EF>),
    /// Hint the length of the next array.  
    HintLen(Var<FC::N>),
    /// Hint an array of variables.
    HintVars(Array<FC, Var<FC::N>>),
    /// Hint an array of field elements.
    HintFelts(Array<FC, Felt<FC::F>>),
    /// Hint an array of extension field elements.
    HintExts(Array<FC, Ext<FC::F, FC::EF>>),
    /// Hint an array of field elements.
    CircuitV2HintFelts(Vec<Felt<FC::F>>),
    /// Hint an array of extension field elements.
    CircuitV2HintExts(Vec<Ext<FC::F, FC::EF>>),
    /// Witness a variable. Should only be used when target is a gnark circuit.
    WitnessVar(Var<FC::N>, u32),
    /// Witness a field element. Should only be used when target is a gnark circuit.
    WitnessFelt(Felt<FC::F>, u32),
    /// Witness an extension field element. Should only be used when target is a gnark circuit.
    WitnessExt(Ext<FC::F, FC::EF>, u32),
    /// Label a field element as the ith public input.
    Commit(Felt<FC::F>, Var<FC::N>),
    /// Registers a field element to the public inputs.
    RegisterPublicValue(Felt<FC::F>),
    /// Operation to halt the program. Should be the last instruction in the program.  
    Halt,

    // Public inputs for circuits.
    /// Asserts that the inputted var is equal the circuit's vkey hash public input. Should only be
    /// used when target is a gnark circuit.
    CircuitCommitVkeyHash(Var<FC::N>),
    /// Asserts that the inputted var is equal the circuit's committed values digest public input.
    /// Should only be used when target is a gnark circuit.
    CircuitCommitCommittedValuesDigest(Var<FC::N>),

    /// BatchFRI loop
    CircuitBatchFRI(
        Box<(
            Ext<FC::F, FC::EF>,
            Vec<Ext<FC::F, FC::EF>>,
            Vec<Ext<FC::F, FC::EF>>,
            Vec<Felt<FC::F>>,
        )>,
    ),

    /// Select based on input bit
    Select(
        Felt<FC::F>,
        Felt<FC::F>,
        Felt<FC::F>,
        Felt<FC::F>,
        Felt<FC::F>,
    ),

    /// Adds two elliptic curve points. (sum, point_1, point_2).
    CircuitV2HintAddCurve(
        Box<(
            SepticCurve<Felt<FC::F>>,
            SepticCurve<Felt<FC::F>>,
            SepticCurve<Felt<FC::F>>,
        )>,
    ),

    /// Select's a variable based on a condition. (select(cond, true_val, false_val) => output).
    /// Should only be used when target is a gnark circuit.
    CircuitSelectV(Var<FC::N>, Var<FC::N>, Var<FC::N>, Var<FC::N>),
    /// Select's a field element based on a condition. (select(cond, true_val, false_val) =>
    /// output). Should only be used when target is a gnark circuit.
    CircuitSelectF(Var<FC::N>, Felt<FC::F>, Felt<FC::F>, Felt<FC::F>),
    /// Select's an extension field element based on a condition. (select(cond, true_val,
    /// false_val) => output). Should only be used when target is a gnark circuit.
    CircuitSelectE(
        Var<FC::N>,
        Ext<FC::F, FC::EF>,
        Ext<FC::F, FC::EF>,
        Ext<FC::F, FC::EF>,
    ),
    /// Converts an ext to a slice of felts. Should only be used when target is a gnark circuit.
    CircuitExt2Felt([Felt<FC::F>; 4], Ext<FC::F, FC::EF>),
    /// Converts a slice of felts to an ext. Should only be used when target is a gnark circuit.
    CircuitFelts2Ext([Felt<FC::F>; 4], Ext<FC::F, FC::EF>),

    // Debugging instructions.
    /// Executes less than (var = var < var).  This operation is NOT constrained.
    LessThan(Var<FC::N>, Var<FC::N>, Var<FC::N>),
    /// Tracks the number of cycles used by a block of code annotated by the string input.
    CycleTracker(String),
    /// Tracks the number of cycles used by a block of code annotated by the string input.
    CycleTrackerV2Enter(String),
    /// Tracks the number of cycles used by a block of code annotated by the string input.
    CycleTrackerV2Exit,

    // Reverse bits exponentiation.
    ExpReverseBitsLen(Ptr<FC::N>, Var<FC::N>, Var<FC::N>),
    /// Reverse bits exponentiation. Output, base, exponent bits.
    CircuitV2ExpReverseBits(Felt<FC::F>, Felt<FC::F>, Vec<Felt<FC::F>>),
}
