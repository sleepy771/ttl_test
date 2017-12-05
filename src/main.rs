extern crate pnet;
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate argparse;

mod collector;
mod probe;

use std::sync::mpsc::{channel};
use std::thread;

use argparse::{ArgumentParser, Collect, StoreTrue};

use collector::{run_collector, SimpleIpfix};
use probe::run_probe;

struct Config {
    verbose: bool,
    interfaces: Vec<String>,
}


fn parse_settings() -> Config {
    let mut cfg = Config {verbose: false, interfaces: vec!["lo".to_string()]};
    {
        let mut ap = ArgumentParser::new();
        ap.set_description("Packet capturer and aggregator");
        ap.refer(&mut cfg.verbose).add_option(&["-v", "--verbose"], StoreTrue, "Enable verbose mode");
        ap.refer(&mut cfg.interfaces).add_argument("INTERFACES", Collect, "Capturing interfaces");
        ap.parse_args_or_exit();
    }
    cfg
}


fn main() {
    env_logger::init().unwrap();
    info!("Starting packet capag");
    let run_cfg = parse_settings();
    let (tx, rx) = channel::<SimpleIpfix>();
    let mut guard_vec = vec![];
    for iface in run_cfg.interfaces {
        let iface_sender = tx.clone();

        let guard = thread::spawn(move || {
            run_probe(iface_sender, iface.as_str());
        });
        guard_vec.push(guard);
    }
    run_collector(rx);
    for guard in guard_vec {
        guard.join().unwrap();
    }
    drop(tx);
//    collector.run_reciever(rx);
    info!("Closing packet packag");
}

