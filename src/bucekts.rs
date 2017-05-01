
use std::hash::{Hash, Hasher, SipHasher};
use std::collections::HashSet;

#[derive(Hash, PartialEq, Eq)]
enum BucketId {
    SourceAddr(Box<[u8]>),
    DestAddr(Box<[u8]>),
    SourcePort(u16),
    DestPort(u16),
    TimestampFrom(u64),
    TimestampTo(u64),
    Arp,
    Tcp,
    Udp,
    Icmp,
}


struct Bucket<T> {
    filters: HashSet<BucketId>,
    data: T
}


impl <T> Hash for Bucket<T> {

    fn hash<H: Hasher>(&self, state: &mut H)
        -> ()
    {
        self.filters.hash(state);
    }
}


impl <T> PartialEq for Bucket<T> {
    
    fn eq(&self, other: &Bucket<T>) -> bool
    {
        self.filters.eq(other.filters)
    }
}


impl <T> Eq for Bucket<T> {}


struct Filter {
    filters: Vec<BucketId>
}
