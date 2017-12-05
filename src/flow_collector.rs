use std::collections::HashMap;

#[derive(Clone, Debug)]
struct Flow {
    source: String,
    destination: String,
    protocol: &'static str,
    size: u32,
    pkt_count: u32,
    additionals: Vec<(&'static str, String)>,
    end_time: u64,
    start_time: u64
}

type FlowHeader = (String, String, &'static str);
type FlowOptions = (u32, u32, Vec<(&'static str, String)>, u64, u64);


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

    pub fn add(&mut self, header: FlowHeader, values: FlowOptions) {
        let new_opts = match self.flows.get_mut(&header) {
            Some(options) => {
                let size = options.0 + values.0;
                let pkts = options.1 + values.1;
                let end_time = 
            }

        };
    }
}
