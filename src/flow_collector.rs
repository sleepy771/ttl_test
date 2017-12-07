use std::collections::HashMap;

#[derive(Clone, Debug)]
struct Flow {
    source: String,
    destination: String,
    protocol: &'static str,
    size: u32,
    pkt_count: u32,
    update: Vec<HashMap<&'static str, String>>
    start_time: u64
    end_time: u64,
}

type FlowHeader = (String, String, &'static str);
type FlowOptions = (u32, u32, Vec<HashMap<&'static str, String>>, u64, u64);
type FlowUpdate = (u32, u32, HashMap<&'static str, String>);
const THRITY_SECONDS: u64 = 30000000000;


struct FlowCollector {
    flows: HashMap<FlowHeader, FlowOptions>,
    flow_timeout: u64,
}


impl FlowCollector {
    pub fn new(timeout: u64) -> FlowCollector {
        FlowCollector {
            flows: HashMap::new(),
            flow_timeout: timeout
        }
    }

    pub fn add(&mut self, header: FlowHeader, values: FlowUpdate) {
        match self.flows.get_mut(&header) {
            Some(options) => {
                *options.0 += values.0;
                *options.1 += values.1;
                *options.4 = time::precise_time_ns();
                (*options).2.push(values.2);
            },
            None => {
                let cap_time = time::precise_time_ns();
                let opts: FlowOptions = (values.0, values.1, vec![values.2], cap_time, cap_time);
                self.flows.insert(header, opts);
            }
        };
    }

    pub fn collect_finished(&mut self) -> Vec<Flow> {
        let current_time = time::precise_time_ns();
        let expired_keys = self.flows.into_iter()
            .filter(|&(key, value)| { value.4 + THRITY_SECONDS < current_time })
            .map(|(key, value)| { key })
            .collect();
    }
}
