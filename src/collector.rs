use std::mem::swap;
use std::collections::HashMap;
// use std::collections::hash_map::Iter;
use std::iter::IntoIterator;
// use std::cmp;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use time;


pub type SimpleIpfix = (String, String, &'static str, Vec<(&'static str, String)>);

#[derive(Debug,Clone)]
pub struct MutWindow {
    samples: HashMap<SimpleIpfix, u32>,
    sampling: u32,
}

impl MutWindow {
    pub fn new(sampling: u32) -> MutWindow {
        let smpl = if sampling < 2u32 {
            1u32
        } else {
            sampling
        };
        MutWindow {
            samples: HashMap::new(),
            sampling: smpl
        }
    }

    pub fn add(&mut self, signature: SimpleIpfix) -> () {
        let new_count = match self.samples.get(&signature) {
            Some(count) => count + self.sampling,
            None => self.sampling
        };
        self.samples.insert(signature, new_count);
    }

    pub fn end_collecting(self) -> Window {
        let time_to = time_now();
        Window {
            samples: self.samples,
            time_to: time_to
        }
    }

//    pub fn len(&self) -> usize {
//        self.samples.len()
//    }
}

#[derive(Debug,Clone)]
pub struct Window {
    samples: HashMap<SimpleIpfix, u32>,
    time_to: u64
}

impl Window {

    pub fn end_time(&self) -> u64 {
        self.time_to
    }

//    pub fn overlaps(&self, window: &Window) -> bool {
//        let max_start_time = cmp::max(window.time_from, self.time_from);
//        let min_end_time = cmp::min(window.time_to, self.time_to);
//        max_start_time >= min_end_time
//    }
    
//    pub fn union(&self, window: &Window) -> Result<Window, &'static str> {
//        if self.overlaps(window) {
//            let min_start_time = cmp::min(self.time_from, window.time_from);
//            let max_end_time = cmp::max(self.time_to, window.time_to);
//            let mut new_flows: HashMap<SimpleIpfix, u32> = HashMap::new();
//            for ipfix in self.samples.keys() {
//                let self_ipfix_count = match self.samples.get(&ipfix) {
//                    Some(count) => count.clone(),
//                    None => 0u32
//                };
//                let window_ipfix_count = match window.samples.get(&ipfix) {
//                    Some(count) => count.clone(),
//                    None => 0u32
//                };
//                new_flows.insert(ipfix.clone(), self_ipfix_count + window_ipfix_count);
//            }
//            Ok(Window {samples: new_flows, time_from: min_start_time, time_to: max_end_time})
//        } else {
//            Err("Windows does not overlap, there is no reason to make union")
//        }
//    }
//    
//    pub fn iter(&self) -> Iter<SimpleIpfix, u32> {
//        self.samples.iter()
//    }
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
    sampling: u32,
    sender: Sender<Window>,
}

impl WindowCollector {
    pub fn new(sampling: u32, sender: Sender<Window>) -> WindowCollector {
        WindowCollector {
            window: None,
            sampling: sampling,
            sender: sender
        }
    }

    pub fn next_window(&mut self) -> () {
        println!("Call next window");
        let mut loco_window = Some(MutWindow::new(self.sampling));
        swap(&mut self.window, &mut loco_window);
        if let Some(window) = loco_window {
            self.sender.send(window.end_collecting()).unwrap();
        };
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

//    pub fn window_size(&self) -> usize {
//        match self.window {
//            Some(ref wnd) => wnd.len(),
//            None => 0
//        }
//    }
}

pub fn run_collector(receiver: Receiver<SimpleIpfix>, sender: Sender<Window>, sampling: u32) {
    let collector = Arc::new(Mutex::new(WindowCollector::new(sampling, sender)));
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
                Err(e) => {
                    error!("Collector receiver error occured: {}", e);
                    drop(receiver);
                    break;
                }
            };
        }
    });
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::new(30, 0));
            let mut col = (*collector_time).lock().unwrap();
            (*col).next_window();
        }
    });
}

pub fn time_now() -> u64 {
    let timespec = time::get_time();
    ((timespec.sec * 1000) as u64) + ((timespec.nsec / 1000000) as u64) 
}
