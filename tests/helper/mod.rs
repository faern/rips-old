use pnet::datalink::{Channel, dummy};
use rips::{EthernetChannel, Interface, NetworkStack};

use std::io;
use std::sync::mpsc::{Receiver, Sender};

pub struct DummyEthernet {
    pub channel: EthernetChannel,
    pub interface: Interface,
    pub inject_handle: Sender<io::Result<Box<[u8]>>>,
    pub read_handle: Receiver<Box<[u8]>>,
}

pub fn dummy_ethernet() -> DummyEthernet {
    let iface = dummy::dummy_interface(0);
    let mac = iface.mac.unwrap();
    let interface = Interface {
        name: iface.name.clone(),
        mac: mac,
    };

    let mut config = dummy::Config::default();
    let read_handle = config.read_handle().unwrap();
    let inject_handle = config.inject_handle().unwrap();

    let channel = match dummy::channel(&iface, config).unwrap() {
        Channel::Ethernet(tx, rx) => {
            EthernetChannel {
                sender: tx,
                write_buffer_size: 4069,
                receiver: rx,
                read_buffer_size: 4096,
            }
        }
        _ => panic!("Invalid channel type returned"),
    };

    DummyEthernet {
        channel: channel,
        interface: interface,
        inject_handle: inject_handle,
        read_handle: read_handle,
    }
}

pub struct DummyStack {
    pub stack: NetworkStack,
    pub interface: Interface,
    pub inject_handle: Sender<io::Result<Box<[u8]>>>,
    pub read_handle: Receiver<Box<[u8]>>,
}

pub fn dummy_stack() -> DummyStack {
    let dummy_ethernet = dummy_ethernet();
    let mut stack = NetworkStack::new();
    stack.add_interface(dummy_ethernet.interface.clone(), dummy_ethernet.channel)
        .expect("Not able to add dummy channel to stack");
    DummyStack {
        stack: stack,
        interface: dummy_ethernet.interface,
        inject_handle: dummy_ethernet.inject_handle,
        read_handle: dummy_ethernet.read_handle,
    }
}

// pub fn dummy_icmp()
//     -> (Ethernet,
//         Arc<Mutex<IcmpListenerLookup>>,
//         Ipv4,
//         Sender<io::Result<Box<[u8]>>>,
//         Receiver<Box<[u8]>>)
// {
//     let icmp_listeners = Arc::new(Mutex::new(HashMap::new()));
//     let icmp_listener = IcmpIpv4Listener::new(icmp_listeners.clone());
//
//     let mut ipv4_ip_listeners = HashMap::new();
//     ipv4_ip_listeners.insert(IpNextHeaderProtocols::Icmp, icmp_listener);
//
//     let mut ipv4_listeners = HashMap::new();
//     ipv4_listeners.insert(Ipv4Addr::new(10, 0, 0, 2), ipv4_ip_listeners);
//
//     let (ethernet, arp_factory, inject_handle, read_handle) =
//         dummy_ipv4(Arc::new(Mutex::new(ipv4_listeners)));
//
//     let mut arp = arp_factory.arp(ethernet.clone());
//     arp.insert(Ipv4Addr::new(10, 0, 0, 1), MacAddr::new(9, 8, 7, 6, 5, 4));
//
// let ip_config = Ipv4Config::new(Ipv4Addr::new(10, 0, 0, 2), 24,
// Ipv4Addr::new(10, 0, 0, 1))
//         .unwrap();
//     let ipv4 = Ipv4::new(ethernet.clone(), arp, ip_config);
//
//
//     (ethernet, icmp_listeners, ipv4, inject_handle, read_handle)
// }
