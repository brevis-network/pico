use common::run_proof;

fn main() {
    // The four compressed points the guest commits: 51*G, 1234^50*G, (1 + 200*50)*G and the
    // 50-fold 5*P + 7*G from P = G. Computed on the host with crates.io curve25519-dalek 4.1.3.
    run_proof!(
        [ED_ADD, ED_DECOMPRESS],
        commits = common::hex(concat!(
            "c309ff1d7a9c00aed8d9aab8ed1fd38839f64f0b4f90829eded7c5f4c0f1428a",
            "6908804f985f41bff223596842394eab7783a98a61975d6e49b8657e7c287d01",
            "1cadeb96189ae5675f61d67f38b2d82048bede3537b739d292e466169edb5d80",
            "cc368d18b263c42348189f9db1dba692bd675eb09ef973a17b4667de6490e1e3",
        ))
    );
}
