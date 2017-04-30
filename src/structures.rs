
use std::collections::VecDeque;
use std::collections::HashMap;
use std::net::IpAddr;

type IPCounter<T> = HashMap<IpAddr, T>;

pub struct Collector {
    _ip_counter: IPCounter<usize>,
    _window: VecDeque<IpAddr>,
    _capacity: usize,
    _entropy: f64
}

impl Collector {
    pub fn new(capacity: usize) -> Collector {
        Collector {
            _ip_counter: IPCounter::new(),
            _window: VecDeque::with_capacity(capacity),
            _capacity: capacity,
            _entropy: 0.,
        }
    }

    pub fn partial_entropy(&self, size: usize) -> f64
    {
        if size == 0 {
            return 0.;
        }
        let p = ((size as f64) / (self._window.len() as f64)) as f64;
        p * p.ln()
    }

    pub fn add(&mut self, ipv4:IpAddr) -> ()
    {
        let c = {
            self._window.push_front(ipv4.clone());
            let count = self._ip_counter.entry(ipv4).or_insert(0);
            *count += 1;
            *count
        };

        self._entropy -= self.partial_entropy(c);

        if self._window.len() == self._capacity {
            if let Some(ip_address) = self._window.pop_back() {
                if let Some(mut count) = self._ip_counter.remove(&ip_address) {
                    self._entropy += self.partial_entropy(count);
                    count -= 1;
                    self._ip_counter.insert(ip_address.clone(), count);
                }
            }
        }
    }

    pub fn get_entropy(&self) -> f64
    {
        self._ip_counter.values().fold(0f64, |entropy, &_count| {entropy - self.partial_entropy(_count) })
    }

    pub fn get_unique(&self) -> usize {
        self._ip_counter.len()
    }

    pub fn get_all(&self) -> usize {
        self._window.len()
    }
}

const COMMON_TTLS: &'static [u8; 4] = &[32, 64, 128, 255];

fn guess_start_ttl(ttl: u8) -> Option<u8>
{
    for &default in COMMON_TTLS {
        if default > ttl {
            return Some(default)
        }
    }
    None
}

fn compute_hops(start_ttl: u8, ttl: u8) -> u8
{
    start_ttl - ttl
}

struct TTLController {
    _ip_counter: IPCounter<u8>
}

impl TTLController {
    pub fn new() -> TTLController
    {
        TTLController { _ip_counter: IPCounter::new() }
    }

    pub fn push(&mut self, ip_addr: IpAddr, ttl: u8) -> ()
    {
        if let Some(start_hops) = guess_start_ttl(ttl) {
            self._ip_counter.insert(ip_addr, compute_hops(start_hops, ttl));
        }
    }

    pub fn matches(&self, ip_addr: &IpAddr, ttl: u8) -> Option<bool>
    {
        match self._ip_counter.get(ip_addr) {
            Some(stored_hops) => {
                if let Some(start_hops) = guess_start_ttl(ttl) {
                    return Some(*stored_hops == start_hops)
                }
                None
            },
            _ => None
        }
    }

    pub fn matches_or_push(&mut self, ip_addr: IpAddr, ttl: u8) -> Option<bool>
    {
        if let Some(start_hops) = guess_start_ttl(ttl) {
            let hops = self._ip_counter.entry(ip_addr).or_insert(start_hops);
            return Some(*hops == ttl)
        }
        None
    }
}
