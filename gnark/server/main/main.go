package main

import (
	"encoding/json"
	"flag"
	"fmt"

	"github.com/brevis-network/pico/gnark/babybear_verifier"
	"github.com/brevis-network/pico/gnark/koalabear_verifier"
	"github.com/brevis-network/pico/gnark/utils"
	"github.com/celer-network/goutils/log"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	bn254cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/labstack/echo"

	"net/http"
	"sync"

	"golang.org/x/crypto/sha3"
)

var (
	httpPort = flag.Int("httpport", 9099, "http json listening port")
	field    = flag.String("field", "kb", "field: kb, bb")
	pkPath   = flag.String("pk", "./data/vm_pk", "path of proving key")
	ccsPath  = flag.String("ccs", "./data/vm_ccs", "path of ccs")

	Pk  = groth16.NewProvingKey(ecc.BN254)
	Ccs = new(bn254cs.R1CS)

	loadReady = false
)

func main() {
	flag.Parse()
	e := echo.New()

	log.Infof("use field: %s", *field)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		log.Infof("start load pk")
		err := utils.ReadProvingKey(*pkPath, Pk)
		log.Infof("end load pk")
		if err != nil {
			log.Fatalf("fail to load pk, err: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		log.Infof("start load ccs")
		err := utils.ReadCcs(*ccsPath, Ccs)
		log.Infof("end load ccs")
		if err != nil {
			log.Fatalf("fail to load ccs, err: %v", err)
		}
	}()
	wg.Wait()
	loadReady = true

	e.POST("/ready", Ready)
	e.POST("/prove", Prove)

	log.Infof("start http %s", fmt.Sprintf("0.0.0.0:%d", *httpPort))
	echoErr := e.Start(fmt.Sprintf("0.0.0.0:%d", *httpPort))
	if echoErr != nil {
		log.Fatalf("fail to start echo server, err: %v", echoErr)
	}
}

func Ready(c echo.Context) error {
	return json.NewEncoder(c.Response()).Encode("success")
}

type ProveReq struct {
	WitnessJsonHex string `json:"witness_json_hex"`
}

type ProveResp struct {
	ProofData string `json:"proof_data"`
}

func Prove(c echo.Context) error {
	payload := &utils.WitnessInput{}
	if err := c.Bind(payload); err != nil { // here unmarshal request body into p
		return c.String(http.StatusInternalServerError, err.Error())
	}

	fullWitness, pubWitness, err := GetWitnessFromHex(*payload)
	if err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}
	pf, err := groth16.Prove(Ccs, Pk, fullWitness, backend.WithProverHashToFieldFunction(sha3.NewLegacyKeccak256()))
	if err != nil {
		return fmt.Errorf("fail to prove groth16: %v", err)
	}

	res, err := utils.GetAggOnChainProof(pf, pubWitness)
	if err != nil {
		return fmt.Errorf("failed to get OnChainProof: %v\n", err)
	}

	return json.NewEncoder(c.Response()).Encode(res)
}

func GetWitnessFromHex(inputs utils.WitnessInput) (fullWitness witness.Witness, pubWitness witness.Witness, err error) {
	if *field == "kb" {
		assigment := koalabear_verifier.NewCircuit(inputs)

		fullWitness, err = frontend.NewWitness(assigment, ecc.BN254.ScalarField())
		if err != nil {
			return
		}
		pubWitness, err = fullWitness.Public()
		if err != nil {
			return
		}
	} else if *field == "bb" {
		assigment := babybear_verifier.NewCircuit(inputs)

		fullWitness, err = frontend.NewWitness(assigment, ecc.BN254.ScalarField())
		if err != nil {
			return
		}
		pubWitness, err = fullWitness.Public()
		if err != nil {
			return
		}
	} else {
		err = fmt.Errorf("invalid field: %s", *field)
		return
	}
	return
}
