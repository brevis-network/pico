use distributed_vm::{
    proof_server::{Proof, ProofServer},
    CompleteProvingRequest,
};
use std::time::Duration;
use tonic::{codec::CompressionEncoding, transport::Server, Request, Response, Status};
use tracing::{info, Level};

#[derive(Debug, Default)]
pub struct ProofTestService;

#[tonic::async_trait]
impl Proof for ProofTestService {
    async fn complete_proving(
        &self,
        request: Request<CompleteProvingRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();

        println!("\n╔════════════════════════════════════════════════════════════════╗");
        println!("║          PROOF COMPLETION NOTIFICATION RECEIVED               ║");
        println!("╚════════════════════════════════════════════════════════════════╝");
        println!("┌────────────────────────────────────────────────────────────────┐");
        println!(
            "│ Status       : {}",
            if req.success {
                "✓ SUCCESS"
            } else {
                "✗ FAILED"
            }
        );
        println!("│ Block Number : {}", req.block_number);
        println!("│ Cycles       : {}", req.cycles);
        println!(
            "│ Proving Time : {} ms ({:.2} seconds)",
            req.proving_milliseconds,
            req.proving_milliseconds as f64 / 1000.0
        );

        if let Some(proof_bytes) = &req.proof {
            println!(
                "│ Proof Size   : {} bytes ({:.2} KB, {:.2} MB)",
                proof_bytes.len(),
                proof_bytes.len() as f64 / 1024.0,
                proof_bytes.len() as f64 / 1024.0 / 1024.0
            );

            // Show first 64 bytes of proof in hex
            let preview_len = proof_bytes.len().min(64);
            println!("│ Proof Preview: (first {} bytes)", preview_len);
            print!("│   ");
            for (i, byte) in proof_bytes[..preview_len].iter().enumerate() {
                print!("{:02x} ", byte);
                if (i + 1) % 16 == 0 && i < preview_len - 1 {
                    print!("\n│   ");
                }
            }
            println!();
        } else {
            println!("│ Proof        : None");
        }

        println!("└────────────────────────────────────────────────────────────────┘");
        println!();

        info!(
            "Received proof completion: block={}, cycles={}, time={}ms, proof_size={}",
            req.block_number,
            req.cycles,
            req.proving_milliseconds,
            req.proof.as_ref().map_or(0, |p| p.len())
        );

        Ok(Response::new(()))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .init();

    // Default to 0.0.0.0:58888 but allow override via env var
    // Using 58888 to avoid conflict with aggregator/subblock services (50053)
    let addr = std::env::var("PROOF_TEST_SERVER_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:58888".to_string())
        .parse()?;

    let service = ProofTestService;

    println!("\n╔════════════════════════════════════════════════════════════════╗");
    println!("║              PROOF TEST SERVER STARTING                        ║");
    println!("╚════════════════════════════════════════════════════════════════╝");
    println!();
    println!("Server listening on: {}", addr);
    println!();
    println!("Configuration:");
    println!("  • Set environment variable in your aggregator:");
    println!("    export PROOF_SERVICE_ADDR=http://{}", addr);
    println!();
    println!("  • Optional: Set cycle count");
    println!("    export PROVING_CYCLES=1000000");
    println!();
    println!("Waiting for proof completion notifications...");
    println!("════════════════════════════════════════════════════════════════\n");

    info!("Starting Proof Test Server on {}", addr);

    Server::builder()
        .tcp_keepalive(Some(Duration::from_secs(60)))
        .http2_keepalive_interval(Some(Duration::from_secs(45)))
        .http2_keepalive_timeout(Some(Duration::from_secs(10)))
        .add_service(
            ProofServer::new(service)
                .accept_compressed(CompressionEncoding::Zstd)
                .send_compressed(CompressionEncoding::Zstd),
        )
        .serve(addr)
        .await?;

    Ok(())
}
