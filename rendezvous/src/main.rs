use std::{
    error::Error,
    net::{Ipv4Addr},
};

use clap::Parser;
use futures::StreamExt;
use libp2p::{autonat, core::{multiaddr::Protocol, Multiaddr}, identity, identify, noise, ping, relay, swarm::{NetworkBehaviour, SwarmEvent}, tcp, yamux, rendezvous};
use tracing_subscriber::EnvFilter;
use std::{fs, path::Path};
use base64::{Engine as _, engine::{general_purpose}};
use anyhow::Result;
use std::path::PathBuf;
use libp2p::rendezvous::server::Event;

#[derive(Debug, Parser)]
#[command(name = "lattica relay")]
struct Opt {
    #[arg(long)]
    port: u16,

    #[arg(long, value_name = "FILE")]
    key_path: Option<PathBuf>,
}

fn load_or_generate_keypair(key_path: Option<PathBuf>) -> Result<identity::Keypair> {
    let path = key_path.unwrap_or_else(|| PathBuf::from("secret.key"));

    if Path::new(&path).exists() {
        let key_b64 = fs::read_to_string(path)?;
        let key_bytes = general_purpose::STANDARD.decode(key_b64.trim())?;
        let keypair = identity::Keypair::from_protobuf_encoding(&key_bytes)?;
        Ok(keypair)
    } else {
        let keypair = identity::Keypair::generate_ed25519();
        let key_bytes = keypair.to_protobuf_encoding()?;
        fs::write(&path, general_purpose::STANDARD.encode(key_bytes))?;
        println!("Generated new keypair and saved to `{}`", path.display());
        Ok(keypair)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let opt = Opt::parse();

    let local_key: identity::Keypair = load_or_generate_keypair(opt.key_path)?;
    println!("Local PeerId: {}", local_key.public().to_peer_id());

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_behaviour(|key| Behaviour {
            rendezvous: rendezvous::server::Behaviour::new(rendezvous::server::Config::default()),
            ping: ping::Behaviour::new(ping::Config::new()),
            identify: identify::Behaviour::new(identify::Config::new(
                "/lattica/1.0.0".to_string(),
                key.public(),
            )),
        })?
        .build();

    let listen_addr_tcp = Multiaddr::empty()
        .with(Protocol::from(Ipv4Addr::UNSPECIFIED))
        .with(Protocol::Tcp(opt.port));

    let listen_addr_quic = Multiaddr::empty()
        .with(Protocol::from(Ipv4Addr::UNSPECIFIED))
        .with(Protocol::Udp(opt.port))
        .with(Protocol::QuicV1);

    swarm.listen_on(listen_addr_tcp)?;
    swarm.listen_on(listen_addr_quic)?;

    loop {
        match swarm.next().await.expect("Infinite Stream.") {
            SwarmEvent::Behaviour(event) => {
                match event {
                    BehaviourEvent::Rendezvous(rendezvous_event) => {
                        match rendezvous_event {
                            Event::DiscoverServed {  enquirer, registrations } =>{
                                tracing::info!("Served peer {} with {} registrations", enquirer, registrations.len());
                            }
                            Event::DiscoverNotServed {  enquirer, error} => {
                                tracing::debug!("Could not serve peer {}: {:?}",enquirer, error);
                            }
                            Event::PeerRegistered { peer, registration  } => {
                                tracing::info!("Peer {} registered for namespace '{}'", peer, registration.namespace);
                            }
                            Event::PeerNotRegistered { peer, namespace, error } => {
                                tracing::debug!("Peer {} not registered for namespace '{}': {:?}",peer, namespace, error);
                            }
                            Event::PeerUnregistered { peer, namespace } => {
                                tracing::info!("Peer {} unregistered for namespace '{}'",peer, namespace);
                            }
                            Event::RegistrationExpired(registration) => {
                                tracing::info!("Registration expired for peer '{}' in namespace '{}'",  registration.record.peer_id(), registration.namespace);
                            }
                        }
                    }
                    _ => {}
                }
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                println!("Listening on {:?}", address);
            }
            _ => {}
        }
    }
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    rendezvous:rendezvous::server::Behaviour,
    ping: ping::Behaviour,
    identify: identify::Behaviour,
}