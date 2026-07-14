//! Connect to the local Zig QUIC echo server with a caller-supplied CA and SNI.

use std::{env, fs::File, io::BufReader, net::SocketAddr, sync::Arc, time::Duration};

use quinn::{ClientConfig, Endpoint};
use rustls::RootCertStore;

fn usage() -> ! {
    eprintln!("usage: cargo run -- <server_addr> <ca_pem> [server_name]");
    std::process::exit(2);
}

fn client_config(ca_path: &str) -> Result<ClientConfig, Box<dyn std::error::Error>> {
    let mut roots = RootCertStore::empty();
    let mut pem = BufReader::new(File::open(ca_path)?);
    for certificate in rustls_pemfile::certs(&mut pem) {
        roots.add(certificate?)?;
    }

    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"hq-interop".to_vec()];
    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?;
    Ok(ClientConfig::new(Arc::new(quic_config)))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| "install rustls ring provider")?;

    let mut args = env::args().skip(1);
    let server_addr: SocketAddr = args.next().unwrap_or_else(|| usage()).parse()?;
    let ca_path = args.next().unwrap_or_else(|| usage());
    let server_name = args.next().unwrap_or_else(|| "localhost".to_owned());
    if args.next().is_some() {
        usage();
    }

    let bind_addr: SocketAddr = "[::]:0".parse()?;
    let mut endpoint = Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_config(&ca_path)?);

    let connection = tokio::time::timeout(
        Duration::from_secs(5),
        endpoint.connect(server_addr, &server_name)?,
    )
    .await??;
    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(b"hello").await?;
    send.finish()?;

    let mut echoed = [0_u8; 5];
    recv.read_exact(&mut echoed).await?;
    if echoed != *b"hello" {
        return Err(format!("unexpected echo {echoed:?}").into());
    }
    if recv.read_chunk(1, true).await?.is_some() {
        return Err("expected echo stream FIN after hello".into());
    }

    println!(
        "rust_quic_echo_client: handshake_done=true echo_bytes={}",
        echoed.len()
    );
    connection.close(0_u32.into(), b"example complete");
    endpoint.wait_idle().await;
    Ok(())
}
