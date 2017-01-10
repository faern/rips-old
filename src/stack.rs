use {EthernetChannel, Interface, RoutingTable, TxError, TxResult, Tx, Payload};
use StackError;
use arp::{self, ArpPayload, ArpTx, ArpTable};
use ethernet::{EthernetRx, EthernetTx, MacAddr, EthernetFields};
// use icmp::{self, IcmpTx};

use ipnetwork::Ipv4Network;

// use ipv4::{self, Ipv4TxImpl};

use pnet::datalink::EthernetDataLinkSender;
use pnet::packet::MutablePacket;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::icmp::IcmpType;
use pnet::packet::ip::IpNextHeaderProtocols;

use rand;
use rand::distributions::{IndependentSample, Range};
use rx;

use std::cmp;
use std::collections::{HashMap, HashSet};
use std::collections::hash_map::Entry;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::sync::{Arc, Mutex, RwLock};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
// use udp::{self, UdpTx};
use util;

pub static DEFAULT_MTU: usize = 1500;
pub static DEFAULT_BUFFER_SIZE: usize = 1024 * 128;
pub static LOCAL_PORT_RANGE_START: u16 = 32768;
pub static LOCAL_PORT_RANGE_END: u16 = 61000;

pub type StackResult<T> = Result<T, StackError>;

pub enum StackInterfaceMsg {
    UpdateArpTable(Ipv4Addr, MacAddr),
    ArpRequest(Ipv4Addr, MacAddr, Ipv4Addr),
    Shutdown,
}

struct StackInterfaceData {
    interface: Interface,
    tx: Arc<Mutex<TxBarrier>>,
    ipv4_addresses: RwLock<HashSet<Ipv4Addr>>,
}

impl StackInterfaceData {
    fn tx(&self) -> DatalinkTx {
        let version = self.tx.lock().unwrap().version();
        DatalinkTx::new(self.tx.clone(), version)
    }

    fn ethernet_tx(&self, dst: MacAddr) -> EthernetTx<DatalinkTx> {
        EthernetTx::new(self.interface.mac, dst, self.tx())
    }

    fn arp_request_tx(&self) -> ArpTx<EthernetTx<DatalinkTx>> {
        let dst = MacAddr(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
        ArpTx::new(self.ethernet_tx(dst))
    }

    fn arp_tx(&self, dst: MacAddr) -> ArpTx<EthernetTx<DatalinkTx>> {
        ArpTx::new(self.ethernet_tx(dst))
    }
}


struct StackInterfaceThread {
    queue: Receiver<StackInterfaceMsg>,
    data: Arc<StackInterfaceData>,
    arp_table: ArpTable,
}

struct StackInterfaceThreadHandle {
    pub handle: Option<JoinHandle<()>>,
    pub tx: Sender<StackInterfaceMsg>,
}

impl Drop for StackInterfaceThreadHandle {
    fn drop(&mut self) {
        if let Err(..) = self.tx.send(StackInterfaceMsg::Shutdown) {
            error!("Unable to send shutdown command to interface thread");
        }
        self.handle.take().unwrap().join().unwrap();
    }
}

impl StackInterfaceThread {
    pub fn spawn(data: Arc<StackInterfaceData>, arp_table: ArpTable) -> StackInterfaceThreadHandle {
        let (thread_tx, rx) = mpsc::channel();
        let stack_interface_thread = StackInterfaceThread {
            queue: rx,
            data: data,
            arp_table: arp_table,
        };
        let thread_handle = thread::spawn(move || {
            stack_interface_thread.run();
        });
        StackInterfaceThreadHandle {
            handle: Some(thread_handle),
            tx: thread_tx,
        }
    }

    fn run(mut self) {
        while let Ok(msg) = self.queue.recv() {
            if !self.process_msg(msg) {
                break;
            }
        }
        debug!("StackInterfaceThread is quitting");
    }

    fn process_msg(&mut self, msg: StackInterfaceMsg) -> bool {
        use self::StackInterfaceMsg::*;
        match msg {
            UpdateArpTable(ip, mac) => self.update_arp(ip, mac),
            ArpRequest(sender_ip, sender_mac, target_ip) => {
                self.handle_arp_request(sender_ip, sender_mac, target_ip)
            }
            Shutdown => return false,
        }
        true
    }

    fn update_arp(&mut self, ip: Ipv4Addr, mac: MacAddr) {
        if self.arp_table.insert(ip, mac) {
            self.data.tx.lock().unwrap().inc();
        }
    }

    fn handle_arp_request(&mut self,
                          sender_ip: Ipv4Addr,
                          sender_mac: MacAddr,
                          target_ip: Ipv4Addr) {
        let has_target_ip = self.data.ipv4_addresses.read().unwrap().contains(&target_ip);
        if has_target_ip {
            debug!("Incoming Arp request for my IP {}", target_ip);
            let mut payload =
                ArpPayload::reply(self.data.interface.mac, target_ip, sender_mac, sender_ip);
            if let Err(e) = tx_send!(|| self.data.arp_tx(sender_mac); &mut payload) {
                error!("Unable to send arp response to {}: {}", sender_ip, e);
            }
        }
    }
}

struct Ipv4Data {
    net: Ipv4Network, /* udp_listeners: Arc<Mutex<udp::UdpListenerLookup>>,
                       * icmp_listeners: Arc<Mutex<icmp::IcmpListenerLookup>>, */
}

/// Represents the stack on one physical interface.
/// The larger `NetworkStack` comprises multiple of these.
pub struct StackInterface {
    data: Arc<StackInterfaceData>,
    mtu: usize,
    _thread_handle: StackInterfaceThreadHandle,
    arp_table: ArpTable,
    ipv4_datas: HashMap<Ipv4Addr, Ipv4Data>, // ipv4_listeners: Arc<Mutex<ipv4::IpListenerLookup>>,
}

impl StackInterface {
    pub fn new(interface: Interface, channel: EthernetChannel) -> StackInterface {
        let stack_interface_data = Arc::new(StackInterfaceData {
            interface: interface,
            tx: Arc::new(Mutex::new(TxBarrier::new(channel.sender, channel.write_buffer_size))),
            ipv4_addresses: RwLock::new(HashSet::new()),
        });

        let arp_table = arp::ArpTable::new();

        let thread_handle = StackInterfaceThread::spawn(stack_interface_data.clone(),
                                                        arp_table.clone());

        let arp_rx = arp_table.arp_rx(thread_handle.tx.clone());

        // let ipv4_listeners = Arc::new(Mutex::new(HashMap::new()));
        // let ipv4_rx = ipv4::Ipv4Rx::new(ipv4_listeners.clone());

        let ethernet_listeners = vec![arp_rx /* , ipv4_rx */];
        let ethernet_rx = EthernetRx::new(ethernet_listeners);
        rx::spawn(channel.receiver, ethernet_rx);

        StackInterface {
            data: stack_interface_data,
            mtu: DEFAULT_MTU,
            _thread_handle: thread_handle,
            arp_table: arp_table,
            ipv4_datas: HashMap::new(), // ipv4_listeners: ipv4_listeners,
        }
    }

    pub fn interface(&self) -> &Interface {
        &self.data.interface
    }

    pub fn ethernet_tx(&self, dst: MacAddr) -> EthernetTx<DatalinkTx> {
        self.data.ethernet_tx(dst)
    }

    pub fn arp_request_tx(&self) -> ArpTx<EthernetTx<DatalinkTx>> {
        self.data.arp_request_tx()
    }

    pub fn arp_tx(&self, dst: MacAddr) -> ArpTx<EthernetTx<DatalinkTx>> {
        self.data.arp_tx(dst)
    }

    pub fn arp_table(&mut self) -> &mut arp::ArpTable {
        &mut self.arp_table
    }

    pub fn add_ipv4(&mut self, ip_net: Ipv4Network) -> StackResult<()> {
        let ip = ip_net.ip();
        match self.ipv4_datas.entry(ip) {
            Entry::Occupied(_) => Err(StackError::IllegalArgument),
            Entry::Vacant(entry) => {
                // let mut proto_listeners = HashMap::new();

                // let udp_listeners = Arc::new(Mutex::new(HashMap::new()));
                // let udp_rx = udp::UdpRx::new(udp_listeners.clone());
                // let udp_ipv4_listener = Box::new(udp_rx) as Box<ipv4::Ipv4Listener>;
                // proto_listeners.insert(IpNextHeaderProtocols::Udp, udp_ipv4_listener);

                // let icmp_listeners = Arc::new(Mutex::new(HashMap::new()));
                // let icmp_rx = icmp::IcmpRx::new(icmp_listeners.clone());
                // let icmp_listener = Box::new(icmp_rx) as Box<ipv4::Ipv4Listener>;
                // proto_listeners.insert(IpNextHeaderProtocols::Icmp, icmp_listener);
                // {
                //     let mut ipv4_listeners = self.ipv4_listeners.lock().unwrap();
                //     ipv4_listeners.insert(ip, proto_listeners);
                // }

                let data = Ipv4Data {
                    net: ip_net, /* udp_listeners: udp_listeners,
                                  * icmp_listeners: icmp_listeners, */
                };
                entry.insert(data);
                self.data.ipv4_addresses.write().unwrap().insert(ip);
                Ok(())
            }
        }
    }

    // pub fn ipv4_sender(&mut self, dst: Ipv4Addr, gw: Option<Ipv4Addr>) ->
    // StackResult<Ipv4Sender> {
    //     let local_dst = gw.unwrap_or(dst);
    //     if let Some(src) = self.closest_local_ip(local_dst) {
    //         let dst_mac = match self.arp_table.get(local_dst) {
    //             Ok(mac) => mac,
    //             Err(rx) => {
    //                 self.arp_sender().send(arp::ArpRequest(self.interface.mac))?;
    //                 rx.recv().unwrap()
    //             }
    //         };
    //         let ethernet_tx = self.ethernet_tx(dst_mac);
    //         Ok(Ipv4TxImpl::new(ethernet_tx, src, dst, self.mtu))
    //     } else {
    //         Err(StackError::IllegalArgument)
    //     }
    // }

    // pub fn icmp_listen<L>(&mut self,
    //                       local_ip: Ipv4Addr,
    //                       icmp_type: IcmpType,
    //                       listener: L)
    //                       -> io::Result<()>
    //     where L: icmp::IcmpListener + 'static
    // {
    //     if let Some(ip_data) = self.ipv4_datas.get(&local_ip) {
    //         let mut icmp_listeners = ip_data.icmp_listeners.lock().unwrap();
    // icmp_listeners.entry(icmp_type).or_insert_with(Vec::new).push(Box::
    // new(listener));
    //         Ok(())
    //     } else {
    //         let msg = "Bind address does not exist on interface".to_owned();
    //         Err(io::Error::new(io::ErrorKind::InvalidInput, msg))
    //     }
    // }

    pub fn get_mtu(&self) -> usize {
        self.mtu
    }

    pub fn set_mtu(&mut self, mtu: usize) {
        self.mtu = mtu;
        self.data.tx.lock().unwrap().inc();
    }

    /// Finds which local IP is suitable as src ip for packets sent to `dst`.
    /// TODO: Smarter algorithm
    fn closest_local_ip(&self, dst: Ipv4Addr) -> Option<Ipv4Addr> {
        for (ip, ip_data) in &self.ipv4_datas {
            if ip_data.net.contains(dst) {
                return Some(*ip);
            }
        }
        None
    }
}

impl Drop for StackInterface {
    fn drop(&mut self) {
        self.data.tx.lock().unwrap().inc();
    }
}

/// The main struct of this library, managing an entire TCP/IP stack. Takes
/// care of ARP, routing tables, threads, TCP resends/fragmentation etc. Most
/// of this is still unimplemented.
#[derive(Default)]
pub struct NetworkStack {
    interfaces: HashMap<Interface, StackInterface>,
    routing_table: Arc<RwLock<RoutingTable>>,
}

impl NetworkStack {
    pub fn new() -> NetworkStack {
        NetworkStack {
            interfaces: HashMap::new(),
            routing_table: Arc::new(RwLock::new(RoutingTable::new())),
        }
    }

    pub fn add_interface(&mut self,
                         interface: Interface,
                         channel: EthernetChannel)
                         -> StackResult<()> {
        match self.interfaces.entry(interface) {
            Entry::Occupied(_) => Err(StackError::InvalidInterface),
            Entry::Vacant(entry) => {
                let interface = entry.key().clone();
                entry.insert(StackInterface::new(interface, channel));
                Ok(())
            }
        }
    }

    pub fn interfaces(&self) -> Vec<Interface> {
        self.interfaces.keys().cloned().collect()
    }

    pub fn interface(&mut self, interface: &Interface) -> StackResult<&mut StackInterface> {
        match self.interfaces.get_mut(interface) {
            Some(i) => Ok(i),
            None => Err(StackError::InvalidInterface),
        }
    }

    pub fn interface_from_name(&mut self, name: &str) -> StackResult<&mut StackInterface> {
        for (interface, stack_interface) in &mut self.interfaces {
            if interface.name == name {
                return Ok(stack_interface);
            }
        }
        Err(StackError::InvalidInterface)
    }

    pub fn routing_table(&mut self) -> Arc<RwLock<RoutingTable>> {
        self.routing_table.clone()
    }

    /// Attach an IPv4 network to an interface.
    /// TODO: Deprecate and make the routing stuff better instead
    pub fn add_ipv4(&mut self, interface: &Interface, ip_net: Ipv4Network) -> StackResult<()> {
        self.interface(interface)?.add_ipv4(ip_net)?;
        self.routing_table.write().unwrap().add_route(ip_net, None, interface.clone());
        Ok(())
    }

    // pub fn ipv4_tx(&mut self,
    //                dst: Ipv4Addr)
    //                -> StackResult<Ipv4TxImpl<EthernetTxImpl<DatalinkTx>>> {
    //     if let Some((gw, interface)) = self.routing_table.route(dst) {
    //         if let Some(stack_interface) = self.interfaces.get_mut(&interface) {
    //             stack_interface.ipv4_tx(dst, gw)
    //         } else {
    //             Err(StackError::IllegalArgument)
    //         }
    //     } else {
    //         Err(StackError::NoRouteToHost)
    //     }
    // }

    // pub fn icmp_tx(&mut self,
    //                dst_ip: Ipv4Addr)
    // ->
    // StackResult<IcmpTx<Ipv4TxImpl<EthernetTxImpl<DatalinkTx>>>> {
    //     let ipv4_tx = self.ipv4_tx(dst_ip)?;
    //     Ok(icmp::IcmpTx::new(ipv4_tx))
    // }

    // pub fn icmp_listen<L>(&mut self,
    //                       local_ip: Ipv4Addr,
    //                       icmp_type: IcmpType,
    //                       listener: L)
    //                       -> io::Result<()>
    //     where L: icmp::IcmpListener + 'static + Clone
    // {
    //     if local_ip == Ipv4Addr::new(0, 0, 0, 0) {
    // let msg = "Rips does not support listening to all interfaces
    // yet".to_owned();
    //         Err(io::Error::new(io::ErrorKind::InvalidInput, msg))
    //     } else {
    //         let mut added_to_interface = false;
    //         for stack_interface in self.interfaces.values_mut() {
    // let result = stack_interface.icmp_listen(local_ip, icmp_type,
    // listener.clone());
    //             added_to_interface |= result.is_ok();
    //         }
    //         if added_to_interface {
    //             Ok(())
    //         } else {
    //             let msg = "Bind address does not exist in stack".to_owned();
    //             Err(io::Error::new(io::ErrorKind::InvalidInput, msg))
    //         }
    //     }
    // }

    // pub fn udp_tx(&mut self,
    //               dst_ip: Ipv4Addr,
    //               src: u16,
    //               dst_port: u16)
    //               -> StackResult<UdpTx<Ipv4TxImpl<EthernetTxImpl<DatalinkTx>>>> {
    //     let ipv4_tx = self.ipv4_tx(dst_ip)?;
    //     Ok(udp::UdpTx::new(ipv4_tx, src, dst_port))
    // }

    // pub fn udp_listen<A, L>(&mut self, addr: A, listener: L) ->
    // io::Result<SocketAddr>
    //     where A: ToSocketAddrs,
    //           L: udp::UdpListener + 'static + Clone
    // {
    //     match util::first_socket_addr(addr)? {
    //         SocketAddr::V4(addr) => self.udp_listen_ipv4(addr, listener),
    //         SocketAddr::V6(_) => {
    //             let msg = "Rips does not support IPv6 yet".to_owned();
    //             Err(io::Error::new(io::ErrorKind::InvalidInput, msg))
    //         }
    //     }
    // }

    // fn udp_listen_ipv4<L>(&mut self, addr: SocketAddrV4, listener: L) ->
    // io::Result<SocketAddr>
    //     where L: udp::UdpListener + 'static + Clone
    // {
    //     let local_ip = addr.ip();
    //     let mut local_port = addr.port();
    //     if local_ip == &Ipv4Addr::new(0, 0, 0, 0) {
    // let msg = "Rips does not support listening to all interfaces
    // yet".to_owned();
    //         Err(io::Error::new(io::ErrorKind::AddrNotAvailable, msg))
    //     } else {
    //         for stack_interface in self.interfaces.values() {
    //             if let Some(ip_data) = stack_interface.ipv4_datas.get(local_ip) {
    // let mut udp_listeners =
    // ip_data.udp_listeners.lock().unwrap();
    //                 if local_port == 0 {
    //                     local_port = self.get_random_port(&*udp_listeners);
    //                 }
    //                 if !udp_listeners.contains_key(&local_port) {
    //                     udp_listeners.insert(local_port, Box::new(listener));
    // return Ok(SocketAddr::V4(SocketAddrV4::new(*local_ip,
    // local_port)));
    //                 } else {
    //                     let msg =
    // format!("Port {} is already occupied on {}",
    // local_port, local_ip);
    // return Err(io::Error::new(io::ErrorKind::AddrInUse,
    // msg));
    //                 }
    //             }
    //         }
    //         let msg = "Bind address does not exist in stack".to_owned();
    //         Err(io::Error::new(io::ErrorKind::InvalidInput, msg))
    //     }
    // }

    // fn get_random_port(&self, listeners: &udp::UdpListenerLookup) -> u16 {
    //     let range = Range::new(LOCAL_PORT_RANGE_START, LOCAL_PORT_RANGE_END);
    //     let mut rng = rand::thread_rng();
    //     let mut port = 0;
    //     while port == 0 {
    //         let n = range.ind_sample(&mut rng);
    //         if !listeners.contains_key(&n) {
    //             port = n;
    //             break;
    //         }
    //     }
    //     port
    // }
}

#[derive(Clone)]
pub struct DatalinkTx {
    tx: Arc<Mutex<TxBarrier>>,
    version: u64,
}

impl DatalinkTx {
    fn new(tx: Arc<Mutex<TxBarrier>>, version: u64) -> Self {
        DatalinkTx {
            tx: tx,
            version: version,
        }
    }
}

impl Tx<()> for DatalinkTx {
    fn send<'p, P>(&mut self, payload: &'p mut P) -> Option<TxResult<()>>
        where P: Payload<()>
    {
        let mut tx = self.tx.lock().expect("Poisoned lock in stack. This is a Rips bug");
        if self.version != tx.version() {
            None
        } else {
            Some(tx.send(payload))
        }
    }
}

pub struct TxBarrier {
    tx: Box<EthernetDataLinkSender>,
    cache_size: usize,
    version: u64,
}

impl TxBarrier {
    pub fn new(tx: Box<EthernetDataLinkSender>, cache_size: usize) -> TxBarrier {
        TxBarrier {
            tx: tx,
            cache_size: cache_size,
            version: 0,
        }
    }

    /// Increments the internal counter by one. Used to invalidate all `Tx`
    /// instances created towards this `TxBarrier`
    pub fn inc(&mut self) {
        self.version = self.version.wrapping_add(1);
        trace!("TxBarrier ticked to {}", self.version);
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    fn send<'p, P>(&mut self, payload: &'p mut P) -> TxResult<()>
        where P: Payload<()>
    {
        let mut packets_left = payload.num_packets();
        let packet_size = payload.packet_size();
        let max_packets_per_call = self.cache_size / packet_size;
        if max_packets_per_call == 0 {
            return Err(TxError::TooLargePayload);
        }
        let mut ethernet_payload = |mut packet: MutableEthernetPacket| {
            payload.build(packet.packet_mut());
        };
        while packets_left > 0 {
            let num_packets = cmp::min(packets_left, max_packets_per_call);
            self.tx
                .build_and_send(num_packets, packet_size, &mut ethernet_payload)
                .expect("Insufficient buffer space")?;
            packets_left -= num_packets;
        }
        Ok(())
    }
}

/// Create a default stack managing all interfaces given by
/// `pnet::datalink::interfaces()`.
pub fn default_stack() -> StackResult<NetworkStack> {
    use pnet::datalink;
    let mut stack = NetworkStack::new();
    for interface in datalink::interfaces() {
        if let Ok(rips_interface) = Interface::try_from(&interface) {
            let mut config = datalink::Config::default();
            config.write_buffer_size = DEFAULT_BUFFER_SIZE;
            config.read_buffer_size = DEFAULT_BUFFER_SIZE;
            let channel = match try!(datalink::channel(&interface, config)
                .map_err(StackError::from)) {
                datalink::Channel::Ethernet(tx, rx) => {
                    EthernetChannel {
                        sender: tx,
                        write_buffer_size: config.write_buffer_size,
                        receiver: rx,
                        read_buffer_size: config.read_buffer_size,
                    }
                }
                _ => unreachable!(),
            };
            try!(stack.add_interface(rips_interface, channel));
        }
    }
    Ok(stack)
}
