module github.com/brevis-network/pico/gnark

go 1.22.10

require (
	github.com/consensys/gnark v0.10.0
	github.com/consensys/gnark-crypto v0.12.2-0.20240215234832-d72fcb379d3e
	github.com/rs/zerolog v1.30.0
	golang.org/x/crypto v0.26.0
)

require (
	github.com/bits-and-blooms/bitset v1.10.0 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/consensys/bavard v0.1.13 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fxamacker/cbor/v2 v2.5.0 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/pprof v0.0.0-20230817174616-7a8ec2ada47b // indirect
	github.com/ingonyama-zk/icicle/v2 v2.0.3 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/testify v1.9.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/sys v0.23.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)

replace (
	github.com/OpenAssetStandards/poseidon-goldilocks-go => github.com/brevis-network/poseidon-goldilocks-go v0.0.0-20240826082508-8017eb90f413
	github.com/consensys/gnark => github.com/celer-network/gnark v0.1.0
	github.com/succinctlabs/gnark-plonky2-verifier => github.com/brevis-network/gnark-plonky2-verifier v0.0.0-20241008110619-a4af874609bc

)
