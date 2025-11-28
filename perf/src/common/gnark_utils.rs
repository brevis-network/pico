use crate::common::bench_field::BenchField;
use anyhow::{anyhow, Error};
use reqwest::blocking::Client;
use std::{
    env,
    path::Path,
    process::{Command, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};
use strum::IntoEnumIterator;

fn run_shell_command(cmd: &str) -> Result<String, Error> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(anyhow!(
            "Command `{}` failed: {}",
            cmd,
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

fn run_docker_command(args: &[&str]) -> Result<String, Error> {
    let output = Command::new("docker")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(anyhow!(
            "Docker command `docker {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

pub fn create_gnark_prover(field: BenchField, download_path: &str) -> Result<(), Error> {
    let current_dir = env::current_dir()?;
    let abs_download_path = current_dir.join(download_path).canonicalize()?;

    let docker_cmd = format!(
        "docker run -d -v {}:/data -p 9099:9099 --name pico_bench brevishub/pico_gnark_server:1.2 -field {}",
        abs_download_path.display(),
        field.to_str(),
    );
    run_shell_command(&docker_cmd)?;

    check_gnark_prover_ready()?;

    Ok(())
}

pub fn stop_gnark_prover() -> Result<(), Error> {
    run_docker_command(&["stop", "pico_bench"])?;

    Ok(())
}

pub fn remove_gnark_prover() -> Result<(), Error> {
    run_docker_command(&["rm", "-f", "pico_bench"])?;

    Ok(())
}

pub fn recreate_gnark_prover(field: BenchField, download_path: &str) -> Result<(), Error> {
    // Stop the container if it is running.
    let _ = stop_gnark_prover();
    sleep(Duration::from_secs(1));

    // Remove container if exists.
    let _ = remove_gnark_prover();
    sleep(Duration::from_secs(1));

    create_gnark_prover(field, download_path)
}

pub fn send_gnark_prove_task(json_req: String) -> Result<String, Error> {
    let client = Client::new();
    tracing::info!("start send witness to gnark prover");

    let response = client
        .post("http://127.0.0.1:9099/prove")
        .header("Content-Type", "application/json")
        .body(json_req.to_string())
        .send()?;

    if !response.status().is_success() {
        return Err(anyhow!(
            "Failed to prove task: {} {}",
            response.status(),
            response.text()?
        ));
    }
    tracing::info!("gnark prover successful");

    response.text().map_err(Into::into)
}

fn check_gnark_prover_ready() -> Result<(), Error> {
    let client = Client::new();
    let start = Instant::now();
    let timeout = Duration::from_secs(120);
    let poll_interval = Duration::from_secs(2);

    loop {
        match client
            .post("http://127.0.0.1:9099/ready")
            .header("Content-Type", "application/json")
            .timeout(Duration::from_secs(2))
            .send()
        {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!("gnark prover is ready");
                break;
            }
            _ => {
                tracing::info!("docker prover not ready for conn, waiting...");
            }
        }

        if start.elapsed() > timeout {
            return Err(anyhow!("wait for docker prover timeout"));
        }
        sleep(poll_interval);
    }

    Ok(())
}

pub fn gnark_prover_exists() -> bool {
    if let Ok(output) = run_docker_command(&[
        "ps",
        "-a",
        "--filter",
        "name=pico_bench",
        "--format",
        "{{.Status}}",
    ]) {
        !output.trim().is_empty()
    } else {
        false
    }
}

pub fn gnark_prover_running() -> bool {
    if let Ok(output) = run_docker_command(&[
        "ps",
        "--filter",
        "name=pico_bench",
        "--format",
        "{{.Status}}",
    ]) {
        !output.trim().is_empty()
    } else {
        false
    }
}

pub fn download_files(field: BenchField) -> Result<(), Error> {
    let url_path = field.url_path();
    let download_dir = get_download_path(field);
    run_shell_command(&format!("mkdir -p {}", download_dir))?;

    for file in &["vm_pk", "vm_vk", "vm_ccs"] {
        let output = format!("{}/{}", download_dir, file);
        if Path::new(&output).exists() {
            println!("File {} already exists. Skipping download.", output);
            continue;
        }
        let url = format!(
            "https://picobench.s3.us-west-2.amazonaws.com/{}/gpu/{}",
            url_path, file
        );
        let cmd = format!("curl -o {} {}", output, url);
        run_shell_command(&cmd)?;
    }

    Ok(())
}

pub fn delete_files(field: BenchField) -> Result<(), Error> {
    let download_dir = get_download_path(field);
    run_shell_command(&format!("rm -rf {}", download_dir))?;

    Ok(())
}

pub fn download_files_all() -> Result<(), Error> {
    for field in BenchField::iter() {
        download_files(field)?;
    }

    Ok(())
}

pub fn delete_files_all() -> Result<(), Error> {
    run_shell_command("rm -rf gnark_downloads")?;

    Ok(())
}

pub fn get_download_path(field: BenchField) -> String {
    format!("gnark_downloads/{}", field.to_str())
}
