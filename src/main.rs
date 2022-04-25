mod querier;
mod zone_iterator;

use crate::querier::{IpFamilyMode, Querier};
use clap::Parser;
use console::style;
use std::net::SocketAddr;
use trust_dns_client::rr::Name;

#[derive(Parser)]
struct Args {
    #[clap(long, short = 'a', default_value_t = SocketAddr::new("192.36.148.17".parse().unwrap(), 53))]
    root_address: SocketAddr,

    #[clap(long, short = 'o', default_value = ".")]
    origin: Name,

    #[clap(long, short = 'f', default_value_t = querier::IpFamilyMode::Any)]
    ip_family_mode: IpFamilyMode,

    zone: Name,
}

fn main() {
    let args = Args::parse();

    let querier = Querier::new(args.ip_family_mode);

    let root_zone = querier.query_zone(args.origin.clone(), args.root_address);

    let mut last_zone = root_zone;

    for (parent, child) in zone_iterator::iter(args.zone.clone(), args.origin) {
        if let Some(addr) = querier::random_address(last_zone.nameservers(), args.ip_family_mode) {
            let parent_addr = SocketAddr::new(addr, 53);
            let parent_zone = last_zone;

            last_zone = querier.query_zone(child.clone(), parent_addr);

            let result = querier.query_trust(&parent_zone, &last_zone);

            match result {
                Ok(trust) => print_trust(trust, parent, child),
                Err(message) => print_error(message, parent, child),
            }
        } else {
            print_error(
                "no usable address found for nameserver".to_string(),
                parent,
                child,
            );
        }
    }
}

fn print_trust(trust: querier::Trust, parent: Name, child: Name) {
    let styled_trust = match trust {
        querier::Trust::Trusted => format!("{}", style("OK").green()),
        querier::Trust::Untrusted(_) => format!("{}", style("Untrusted").red()),
    };

    let message = match trust {
        querier::Trust::Untrusted(ref reason) => format!(" - {reason}"),
        _ => "".to_string(),
    };

    let line = format!("[{styled_trust}] {parent} -> {child}{message}");

    match trust {
        querier::Trust::Trusted => println!("{}", line),
        querier::Trust::Untrusted(_) => eprintln!("{}", line),
    };
}

fn print_error(message: String, parent: Name, child: Name) {
    eprintln!("[{}] {parent} -> {child} - {message}", style("Error").red());
}
