use std::{error::Error, net::{Ipv4Addr}};
use clap::Parser;
use futures::StreamExt;
use libp2p::{core::{multiaddr::Protocol, Multiaddr}, identity, identify, noise, ping, swarm::{NetworkBehaviour, SwarmEvent}, tcp, yamux, gossipsub};
use tracing_subscriber::EnvFilter;
use std::{fs, path::Path};
use base64::{Engine as _, engine::{general_purpose}};
use anyhow::Result;
use std::path::PathBuf;
use libp2p::gossipsub::MessageAuthenticity;

#[derive(Debug, Parser)]
#[command(name = "lattica bootstrap")]
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

    let gossipsub_config = gossipsub::Config::default();
    let mut gossipsub = gossipsub::Behaviour::new(MessageAuthenticity::Signed(local_key.clone()), gossipsub_config).unwrap();
    let topic = gossipsub::IdentTopic::new("p2p-circuit-broadcast");
    gossipsub.subscribe(&topic).unwrap();

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_behaviour(|key| Behaviour {
            ping: ping::Behaviour::new(ping::Config::new()),
            identify: identify::Behaviour::new(identify::Config::new(
                "/lattica/1.0.0".to_string(),
                key.public(),
            )),
            gossipsub,
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
                    BehaviourEvent::Gossipsub(gossipsub_event) => {
                        match gossipsub_event {
                            gossipsub::Event::Message { message, .. } => {
                                let topic = message.topic.as_str();
                                match topic {
                                    "p2p-circuit-broadcast" => {
                                        if let Ok(addr_str) = std::str::from_utf8(&message.data) {
                                            if let Some(source_peer_id) = message.source {
                                                if let Ok(addr) = addr_str.parse::<Multiaddr>() {
                                                    swarm.add_peer_address(source_peer_id, addr.clone());
                                                }
                                            } else {
                                                println!("Gossipsub message message.source error")
                                            }
                                        } else {
                                            println!("Gossipsub std::str::from_utf8 error")
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            _ => {}
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
    ping: ping::Behaviour,
    identify: identify::Behaviour,
    gossipsub: gossipsub::Behaviour,
}