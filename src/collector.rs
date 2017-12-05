extern crate pnet;
extern crate time;
extern crate timer;
extern crate chrono;

use pnet::packet::ip::IpNextHeaderProtocol;
use std::net::IpAddr;
use std::collections::HashMap;
use std::iter::{IntoIterator, Iterator};
use std::cmp;
use std::sync::mpsc::{Sender, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;


pub type SimpleIpfix = (IpAddr, u16, IpAddr, u16, IpNextHeaderProtocol);
pub type IpfixCounter = (SimpleIpfix, u32);
pub type TimedIpfixCounter = (SimpleIpfix, u32, u64, u64);

#[derive(Debug,Clone)]
pub struct MutWindow {
    samples: HashMap<SimpleIpfix, u32>,
    time_from: u64,
}

impl MutWindow {
    pub fn new() -> MutWindow {
        MutWindow {samples: HashMap::new(), time_from: time::precise_time_ns()}
    }

    pub fn contains(&self, signature: &SimpleIpfix) -> bool {
        self.samples.contains_key(signature)
    }

    pub fn add(&mut self, signature: SimpleIpfix) -> () {
        let new_count = match self.samples.get(&signature) {
            Some(count) => count + 1,
            None => 1
        };
        self.samples.insert(signature, new_count);
    }

    pub fn end_collecting(mut self) -> Window {
        let time_to = time::precise_time_ns();
        Window {samples: self.samples, time_from: self.time_from, time_to: time_to}
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }
}

#[derive(Debug,Clone)]
pub struct Window {
    samples: HashMap<SimpleIpfix, u32>,
    time_from: u64,
    time_to: u64
}

impl Window {
    pub fn start_time(&self) -> u64 {
        self.time_from
    }

    pub fn end_time(&self) -> u64 {
        self.time_to
    }

    pub fn overlaps(&self, window: &Window) -> bool {
        let max_start_time = cmp::max(window.time_from, self.time_from);
        let min_end_time = cmp::min(window.time_to, self.time_to);
        max_start_time >= min_end_time
    }
    
    pub fn union(&self, window: &Window) -> Result<Window, &'static str> {
        if self.overlaps(window) {
            let min_start_time = cmp::min(self.time_from, window.time_from);
            let max_end_time = cmp::max(self.time_to, window.time_to);
            let mut new_flows: HashMap<SimpleIpfix, u32> = HashMap::new();
            for ipfix in self.samples.keys() {
                let self_ipfix_count = match self.samples.get(&ipfix) {
                    Some(count) => count.clone(),
                    None => 0u32
                };
                let window_ipfix_count = match window.samples.get(&ipfix) {
                    Some(count) => count.clone(),
                    None => 0u32
                };
                new_flows.insert(ipfix.clone(), self_ipfix_count + window_ipfix_count);
            }
            Ok(Window {samples: new_flows, time_from: min_start_time, time_to: max_end_time})
        } else {
            Err("Windows does not overlap, there is no reason to make union")
        }
    }
}

impl IntoIterator for Window {
    type Item = (SimpleIpfix, u32);
    type IntoIter = ::std::collections::hash_map::IntoIter<SimpleIpfix, u32>;

    fn into_iter(self) -> Self::IntoIter {
        self.samples.into_iter()
    }
}


pub struct WindowCollector {
    window: Option<MutWindow>,
//    sender: Sender<Window>,
    window_capacity: usize,
    is_running: bool
}

impl WindowCollector {
    pub fn new() -> WindowCollector {
        WindowCollector {
//            sender: sender,
            window: None,
            window_capacity: 20,
            is_running: false
        }
    }

    pub fn next_window(&mut self) -> () {
        println!("Call next window");
        if let Some(ref window) = self.window {
//            self.sender.send(window.clone().end_collecting()).unwrap();
            let wnd = window.clone().end_collecting();
            println!("New window t=[{}, {}]", wnd.time_from, wnd.time_to);
            for (ipfix, cnt) in wnd.into_iter() {
                println!("{:?}: {}", ipfix, cnt);
            }
        };
        self.window = Some(MutWindow::new());
    }

    pub fn add(&mut self, signature: SimpleIpfix) -> Result<(), &'static str> {
        match self.window {
            Some(ref mut window) => {
                window.add(signature);
                Ok(())
            },
            None => Err("MutWindow was not initialized, run `WindowCollector::next_window` first")
        }
    }

    pub fn window_size(&self) -> usize {
        match self.window {
            Some(ref wnd) => wnd.len(),
            None => 0
        }
    }
}

pub fn run_collector(receiver: Receiver<SimpleIpfix>) -> Arc<Mutex<WindowCollector>> {
    let mut collector = Arc::new(Mutex::new(WindowCollector::new()));
    {
        let mut col = collector.lock().unwrap();
        (*col).next_window();
    };

    let collector_loop = collector.clone();
    let collector_time = collector.clone();

    thread::spawn(move || {
        loop {
            match receiver.recv() {
                Ok(ipfix) => {
                    let mut collector_guard = (*collector_loop).lock().unwrap();
                    (*collector_guard).add(ipfix).unwrap();
                },
                Err(_) => panic!("Somethign happend")
            };
        }
    });
    println!("Starting timer");
    let timer = timer::Timer::new();
    let guard = timer.schedule_repeating(chrono::Duration::seconds(5), move || {
        println!("Call next window");
        let mut collector_guard = (*collector_time).lock().unwrap();
        (*collector_guard).next_window();
    });
    collector
}
