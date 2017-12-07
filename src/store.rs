use std::sync::mpsc::Receiver;
use std::thread;
use influx_db_client::{Client, Point, Points, Value, Precision};

use collector::{SimpleIpfix, Window};
use ::CONFIG;

lazy_static! {
    static ref INFLUX: Client = Client::new(CONFIG.influx_host.as_str(), CONFIG.influx_db.as_str());
}


pub fn run_storer(receiver: Receiver<Window>) {

    thread::spawn(move || {
        loop {
            match receiver.recv() {
                Ok(window) => {
                    println!("{} μs", window.end_time());
                    save_window(window);
                },
                Err(e) => {
                    error!("Storer receiver error occured: {}", e);
                    drop(receiver);
                    break;
                }
            }
        }
    });
    
}


pub fn save_window(window: Window) {
    INFLUX.write_points(create_points(window), Some(Precision::Milliseconds), None).unwrap();
}


fn create_points(window: Window) -> Points {
    let timestamp = window.end_time();
    let points: Vec<Point> = window.into_iter()
        .map(|(ipfix, cnt)| { create_point(ipfix, cnt, timestamp) })
        .collect();
    Points::create_new(points)
}


fn create_point(ipfix: SimpleIpfix, cnt: u32, timestamp: u64) -> Point {
    let mut point: Point = point!("pcap_headers");
    let (src_ip, src_port) = parse_address(ipfix.0); 
    let (dst_ip, dst_port) = parse_address(ipfix.1);
    point.add_tag("src_ip", src_ip);
    point.add_tag("src_port", src_port);
    point.add_tag("dst_ip", dst_ip);
    point.add_tag("dst_port", dst_port);
    point.add_tag("proto", Value::String(ipfix.2.to_string()));
    point.add_timestamp(timestamp as i64);
    for (tag_name, tag_value) in ipfix.3 {
        point.add_tag(tag_name.to_string(), Value::String(tag_value));
    }
    point.add_field("cnt", Value::Integer(cnt as i64));
    point
}


fn parse_address(address: String) -> (Value, Value) {
    let address: Vec<&str> = address.split(':').collect();
    match address.len() {
        2 => {
            (Value::String(address[0].to_string()), Value::String(address[1].to_string()))
        }
        _ => {
            (Value::String(address[0].to_string()), Value::String("-".to_string()))
        }
    }
}
