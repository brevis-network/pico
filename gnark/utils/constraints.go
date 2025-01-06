package utils

import (
	"encoding/hex"
	"fmt"
	bn254_fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"math/big"
	"os"
)

type Groth16Proof struct {
	A             [2]string    `json:"a"`
	B             [2][2]string `json:"b"`
	C             [2]string    `json:"c"`
	Commitment    [2]string    `json:"commitment"`
	CommitmentPok [2]string    `json:"commitment_pok"`
}

func ReadProvingKey(filename string, pk groth16.ProvingKey) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = pk.UnsafeReadFrom(f)
	return err
}

func ReadVerifyingKey(filename string, vk groth16.VerifyingKey) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = vk.UnsafeReadFrom(f)
	return err
}

func WriteProvingKey(filename string, pk groth16.ProvingKey) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	_, err = pk.WriteTo(f)
	if err != nil {
		return err
	}
	return nil
}

func WriteVerifyingKey(filename string, vk groth16.VerifyingKey) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}

	_, err = vk.WriteTo(f)
	if err != nil {
		return err
	}
	return nil
}

func GetAggOnChainProof(proof groth16.Proof, pubWitness witness.Witness) (string, error) {
	a, b, c, _, _ := ExportProof(proof)
	var A [2]string
	for i := 0; i < 2; i++ {
		A[i] = Encode(a[i].Bytes())
	}

	var B [2][2]string
	for i := 0; i < 2; i++ {
		for j := 0; j < 2; j++ {
			B[i][j] = Encode(b[i][j].Bytes())
		}
	}

	var C [2]string
	for i := 0; i < 2; i++ {
		C[i] = Encode(c[i].Bytes())
	}

	/*var Commitment [2]string
	for i := 0; i < 2; i++ {
		Commitment[i] = Encode(commitment[i].Bytes())
	}

	var CommitmentPok [2]string
	for i := 0; i < 2; i++ {
		CommitmentPok[i] = Encode(commitmentPok[i].Bytes())
	}*/

	proofData := Groth16Proof{
		A: A,
		B: B,
		C: C,
		//Commitment:    Commitment,
		//CommitmentPok: CommitmentPok,
	}

	var result = ""
	result += proofData.A[0] + ","
	result += proofData.A[1] + ","
	result += proofData.B[0][0] + ","
	result += proofData.B[0][1] + ","
	result += proofData.B[1][0] + ","
	result += proofData.B[1][1] + ","
	result += proofData.C[0] + ","
	result += proofData.C[1] + ","
	//result += proofData.Commitment[0] + ","
	//result += proofData.Commitment[1] + ","
	//result += proofData.CommitmentPok[0] + ","
	//result += proofData.CommitmentPok[1] + ","

	fmt.Printf("proofData.A[0]: %s \n", proofData.A[0])
	fmt.Printf("proofData.A[1]: %s \n", proofData.A[1])

	fmt.Printf("proofData.B[0][0]: %s \n", proofData.B[0][0])
	fmt.Printf("proofData.B[0][1]: %s \n", proofData.B[0][1])
	fmt.Printf("proofData.B[1][0]: %s \n", proofData.B[1][0])
	fmt.Printf("proofData.B[1][1]: %s \n", proofData.B[1][1])

	fmt.Printf("proofData.C[0]: %s \n", proofData.C[0])
	fmt.Printf("proofData.C[1]: %s \n", proofData.C[1])

	/*fmt.Printf("proofData.Commitment[0]: %s \n", proofData.Commitment[0])
	fmt.Printf("proofData.Commitment[1]: %s \n", proofData.Commitment[1])
	fmt.Printf("proofData.CommitmentPok[0]: %s \n", proofData.CommitmentPok[0])
	fmt.Printf("proofData.CommitmentPok[1]: %s \n", proofData.CommitmentPok[1])*/

	// decode witness

	swVector := pubWitness.Vector().(bn254_fr.Vector)

	// 7 public input
	for i := 0; i < len(swVector); i++ {
		var data [32]byte
		swVector[i].BigInt(new(big.Int)).FillBytes(data[:])
		fmt.Printf("witness_%d: %s \n", i, Encode(data[:]))
		if i == len(swVector)-1 {
			result += Encode(data[:])
		} else {
			result += Encode(data[:]) + ","
		}
	}
	return result, nil
}

// only for bn254
func ExportProof(proof groth16.Proof) (a [2]*big.Int, b [2][2]*big.Int, c [2]*big.Int, commitment [2]*big.Int, commitmentPok [2]*big.Int) {
	bn254Proof := proof.(*groth16_bn254.Proof)
	// proof.Ar, proof.Bs, proof.Krs
	a[0] = bn254Proof.Ar.X.BigInt(new(big.Int))
	a[1] = bn254Proof.Ar.Y.BigInt(new(big.Int))

	b[0][0] = bn254Proof.Bs.X.A1.BigInt(new(big.Int))
	b[0][1] = bn254Proof.Bs.X.A0.BigInt(new(big.Int))
	b[1][0] = bn254Proof.Bs.Y.A1.BigInt(new(big.Int))
	b[1][1] = bn254Proof.Bs.Y.A0.BigInt(new(big.Int))

	c[0] = bn254Proof.Krs.X.BigInt(new(big.Int))
	c[1] = bn254Proof.Krs.Y.BigInt(new(big.Int))

	//commitment[0] = bn254Proof.Commitments[0].X.BigInt(new(big.Int))
	//commitment[1] = bn254Proof.Commitments[0].Y.BigInt(new(big.Int))

	//commitmentPok[0] = bn254Proof.CommitmentPok.X.BigInt(new(big.Int))
	//commitmentPok[1] = bn254Proof.CommitmentPok.Y.BigInt(new(big.Int))
	return
}

// Encode encodes b as a hex string with 0x prefix.
func Encode(b []byte) string {
	enc := make([]byte, len(b)*2+2)
	copy(enc, "0x")
	hex.Encode(enc[2:], b)
	return string(enc)
}
