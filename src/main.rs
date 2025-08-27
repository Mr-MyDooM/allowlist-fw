use std::net::{IpAddr, SocketAddr};
use std::process::Command;

use trust_dns_resolver::config::{ResolverConfig, ResolverOpts, NameServerConfig, Protocol};
use trust_dns_resolver::TokioAsyncResolver;
use tokio::runtime::Runtime;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "allowlist-fw", version, about = "Windows Firewall Allowlist Tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Apply allowlist firewall rules
    Run,
    /// Restore firewall defaults
    Restore,
}

/// DNS servers we’ll use for resolving allowed domains
const DNS_SERVERS: &[&str] = &["8.8.8.8", "1.1.1.1"];

/// Build a custom resolver config with our DNS servers
fn custom_resolver(servers: &[&str]) -> (ResolverConfig, ResolverOpts) {
    let mut cfg = ResolverConfig::new();

    for s in servers {
        if let Ok(ip) = s.parse::<IpAddr>() {
            let ns = NameServerConfig {
                socket_addr: SocketAddr::new(ip, 53),
                protocol: Protocol::Udp,
                tls_dns_name: None,
                trust_negative_responses: true,
                bind_addr: None,
            };
            cfg.add_name_server(ns);
        }
    }

    (cfg, ResolverOpts::default())
}


/// Run `netsh advfirewall firewall add rule ...`
fn run_netsh(args: &[&str]) -> std::io::Result<()> {
    let status = Command::new("netsh")
        .arg("advfirewall")
        .arg("firewall")
        .arg("add")
        .arg("rule")
        .args(args)
        .status()?;
    if !status.success() {
        eprintln!("netsh failed: {:?}", status);
    }
    Ok(())
}

/// Allow traffic only for the given host/IPs
fn allow_host(name: &str, host_ips: &[String]) -> std::io::Result<()> {
    let mut args: Vec<String> = vec![
        format!("name={}", name),
        "dir=out".to_string(),
        "action=allow".to_string(),
    ];

    if !host_ips.is_empty() {
        args.push(format!("remoteip={}", host_ips.join(",")));
    }

    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    run_netsh(&args_ref)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rt = Runtime::new()?;

    rt.block_on(async {
        let (cfg, opts) = custom_resolver(DNS_SERVERS);
        let resolver = TokioAsyncResolver::tokio(cfg, opts);

        // Allowed domains
        let domains = vec![
            "www.google.com",
            "drive.google.com",
            "www.indiapost.gov.in",
            "www.amazon.in",
        ];

        for d in domains {
            match resolver.lookup_ip(d).await {
                Ok(lookup) => {
                    let ips: Vec<String> = lookup.iter().map(|ip| ip.to_string()).collect();
                    println!("Resolved {} -> {:?}", d, ips);
                    allow_host(d, &ips)?;
                }
                Err(e) => eprintln!("Failed to resolve {}: {}", d, e),
            }
        }

        // Default: block all outbound traffic
        Command::new("netsh")
            .args([
                "advfirewall", "set", "allprofiles",
                "firewallpolicy", "blockinbound,blockoutbound",
            ])
            .status()?;

        Ok::<_, Box<dyn std::error::Error>>(())
    })?;

    Ok(())
}
