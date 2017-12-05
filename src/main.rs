extern crate pnet;

mod collector;
mod probe;

use std::sync::mpsc::{channel, Sender, Receiver};
use std::thread;

use collector::{run_collector, WindowCollector, SimpleIpfix};
use probe::run_probe;

fn main() {
    let (tx, rx) = channel::<SimpleIpfix>();
    let guard = thread::spawn(move || {
        run_probe(tx, "wlp2s0");
    });
    run_collector(rx);
    guard.join().unwrap();
//    collector.run_reciever(rx);
}

