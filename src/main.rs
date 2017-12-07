extern crate pnet;
#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;
extern crate env_logger;
extern crate argparse;
extern crate time;
#[macro_use]
extern crate influx_db_client;

mod collector;
mod probe;
mod store;

use std::sync::mpsc::{channel};
use std::thread;

use argparse::{ArgumentParser, Collect, StoreTrue, Store};

use collector::{run_collector, SimpleIpfix, Window};
use probe::run_probe;
use store::run_storer;

struct Config {
    verbose: bool,
    interfaces: Vec<String>,
    sampling: u32,
}


fn parse_settings() -> Config {
    let mut cfg = Config {verbose: false, interfaces: vec!["lo".to_string()], sampling: 1u32};
    {
        let mut ap = ArgumentParser::new();
        ap.set_description("Packet capturer and aggregator");
        ap.refer(&mut cfg.verbose).add_option(&["-v", "--verbose"], StoreTrue, "Enable verbose mode");
        ap.refer(&mut cfg.interfaces).add_argument("INTERFACES", Collect, "Capturing interfaces");
        ap.refer(&mut cfg.sampling).add_option(&["-s", "--sampling"], Store, "How much packets are not captured");
        ap.parse_args_or_exit();
    }
    cfg
}


fn main() {
    env_logger::init().unwrap();
    info!("Starting packet capag");
    let run_cfg = parse_settings();
    let (tx, rx) = channel::<SimpleIpfix>();
    let (window_tx, window_rx) = channel::<Window>();
    let mut guard_vec = vec![];
    let sampling = run_cfg.sampling;
    for iface in run_cfg.interfaces {
        let iface_sender = tx.clone();

        let guard = thread::spawn(move || {
            run_probe(iface_sender, iface.as_str(), sampling);
        });
        guard_vec.push(guard);
    }
    run_collector(rx, window_tx, sampling);
    run_storer(window_rx);
    for guard in guard_vec {
        guard.join().unwrap();
    }
    drop(tx);
    info!("Closing packet packag");
}

