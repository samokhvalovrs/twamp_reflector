use std::fmt::Display;
use std::fmt::Error;
use std::fmt::Write;
//use std::intrinsics::size_of;
use std::io::IoSliceMut;
use std::io::stdout;
use std::net::SocketAddr;
use std::net::SocketAddrV6;
use std::net::UdpSocket;
use std::os::fd::AsFd;
use std::ptr::null;
use std::str::FromStr;
use std::thread;
use std::net;
use std::time::Duration;
use std::usize;
use std::ascii::escape_default;
use std::str;
use std:: env;


use nix::cmsg_space;
use nix::libc::getsockopt;
use nix::libc::setsockopt;
use nix::sys::socket::*;
use nix::sys::socket::sockopt::Ipv6TClass;
use nix::sys::socket::sockopt::Ipv6Ttl;
use nix::sys::time::*;
use nix::sys::uio::IoVec;
use std::time::*;
use nix::libc::*;

use core::ptr;
use std::{ os::unix::io::AsRawFd};

pub use nix::libc::{
    cmsghdr,
    msghdr,
    sa_family_t,
    sockaddr,
    sockaddr_in,
    sockaddr_in6,
    sockaddr_storage,
    sockaddr_un,
};

/*
unsafe fn SocketServer() {
  let sock = nix::libc::socket( AddressFamily::Inet6 as i32, SockType::Datagram as i32, 0 );
 
  let addr_in6: nix::libc::in6_addr = in6_addr{ s6_addr: ([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1])};
  let sock_addr_in6: nix::libc::sockaddr_in6 = sockaddr_in6 { sin6_family: (AddressFamily::Inet6 as u16), sin6_port: (9999), sin6_flowinfo: (0), sin6_addr: (addr_in6), sin6_scope_id: (0) };
  let addr: nix::libc::sockaddr = nix::libc::sockaddr{ sa_family: 10, sa_data: []};
  let bnd = nix::libc::bind( sock, &addr, 28 ); 
}
*/

/*#define IPV6_RECVHOPLIMIT	51
#define IPV6_HOPLIMIT		52
#define IPV6_RECVHOPOPTS	53
#define IPV6_HOPOPTS		54
#define IPV6_RTHDRDSTOPTS	55
#define IPV6_RECVRTHDR		56
#define IPV6_RTHDR		57
#define IPV6_RECVDSTOPTS	58
#define IPV6_DSTOPTS		59
#define IPV6_RECVPATHMTU	60
#define IPV6_PATHMTU		61
#define IPV6_DONTFRAG		62

/* Advanced API (RFC3542) (2).  */
#define IPV6_RECVTCLASS		66
#define IPV6_TCLASS		67 */

use core::array::TryFromSliceError;

const sender_offset: usize = 14;
fn FillReflectedPacket( recv_buffer: &[u8], send_buffer: &mut [u8], hl: i32, tv: nix::libc::timeval ) -> usize {
  let offset: usize = 0;
  send_buffer[offset..offset+4].copy_from_slice(&recv_buffer[0..14]);
  send_buffer[sender_offset..14].copy_from_slice(&recv_buffer[0..14]);
  offset
}

unsafe fn TwampReflector( udp_sock: UdpSocket, TraffClass: Option<i32> ) -> Result<(), String> {
  println!("Twamp reflector");
  let sock = udp_sock.as_raw_fd();

  match nix::sys::socket::setsockopt(sock, sockopt::ReceiveTimestamp, &true) {
    Ok(()) => println!("option ReceiveTimestamp set"),
    Err(error) => return Result::Err(format!("Cannot set sockopt ReceiveTimestamp: error {}", error)),
  }
  
  if let Some(tc) = TraffClass {
    match nix::sys::socket::setsockopt(sock, sockopt::Ipv6TClass, &tc) {
      Ok(()) => println!("option Ipv6TClass set"),
      Err( error ) => return Result::Err(format!("Cannot set sockopt Ipv6TClass: error {}", error)),
    }
  }

  match nix::sys::socket::setsockopt(sock, sockopt::Ipv6Ttl, &255) {
    Ok(()) => println!("option Ipv6Ttl set"),
    Err( error ) => return Result::Err(format!("Cannot set sockopt Ipv6Ttl: error {}", error)),
  }

  let mut yes: [u8;4] = [0,0,0,1];
  let mut r = setsockopt(sock, nix::libc::IPPROTO_IPV6, nix::libc::IPV6_RECVHOPLIMIT, yes.as_mut_ptr() as *const c_void, 4 );
  if r < 0  {
    return Result::Err(format!("Cannot set sockopt IPV6_RECVHOPLIMIT {}", r));
  }
  r = setsockopt(sock, nix::libc::IPPROTO_IPV6, nix::libc::IPV6_RECVTCLASS, yes.as_mut_ptr() as *const c_void, 4);
  if r < 0  {
    return Result::Err(format!("Cannot set sockopt IPV6_RECVTCLASS {}", r));
  }

  let mut addr_buff: [u8;32] = [0u8;32];
  let mut recv_buff: [u8;2048] = [0u8;2048];
  let mut send_buff: [u8;2048] = [0u8;2048];
  let mut control_buff: [u8;2048] = [0u8;2048];
  let mut data: *mut u8;
  let mut hl = 0;
  let mut tc = 0;
  let mut tv: nix::libc::timeval = nix::libc::timeval{ tv_sec: 0, tv_usec: 0};
  let mut io_vec: iovec = iovec { iov_base: (recv_buff.as_mut_ptr() as *mut c_void), iov_len: (2048) };
  let mut message: msghdr = msghdr { msg_name: addr_buff.as_mut_ptr() as *mut c_void, msg_namelen: (32), msg_iov: (&mut io_vec), msg_iovlen: (1), msg_control: (control_buff.as_mut_ptr() as *mut c_void), msg_controllen: (2048), msg_flags: (0) };
   
  loop {
    
    println!("recvmsg calling");
    let recved = nix::libc::recvmsg( sock, &mut message, 0); 
    println!("recved: {} message cl {} flags {}", recved, message.msg_controllen, message.msg_flags);
    if recved < 0 {
     return Result::Err(format!("recv error {}", recved));
    }
    let mut c_hdr_ref = CMSG_FIRSTHDR( &message as *const _);  
    while !c_hdr_ref.is_null() {
      println!("cmsg_level: {}, cmsg_type: {}", (*c_hdr_ref).cmsg_level, (*c_hdr_ref).cmsg_type);
      data = CMSG_DATA(c_hdr_ref);
      match ((*c_hdr_ref).cmsg_level, (*c_hdr_ref).cmsg_type) {      
        (nix::libc::IPPROTO_IPV6, nix::libc::IPV6_HOPLIMIT) => {
          hl = ptr::read_unaligned(data as *const _);
          println!("hl = {}", hl);
        },
        (nix::libc::IPPROTO_IPV6, nix::libc::IPV6_TCLASS) => {
          tc = ptr::read_unaligned(data as *const _);
          println!("tc = {}", tc);
        },
        (SOL_SOCKET, SCM_TIMESTAMP) => {
          tv = ptr::read_unaligned(data as *const _);
          println!("tv = {} + {}", tv.tv_sec, tv.tv_usec);
        },
        (_, _) => {
          println!("unknown cmsg_level: {}, cmag_type: {}", (*c_hdr_ref).cmsg_level, (*c_hdr_ref).cmsg_type); 
        },
      }
      c_hdr_ref = CMSG_NXTHDR(&message as *const _, c_hdr_ref);
    }

    if tc != 0 {
      match nix::sys::socket::setsockopt(sock, sockopt::Ipv6TClass, &tc) {
        Ok(()) => println!("option Ipv6TClass set"),
        Err( error ) => break,
      }
    }
   
    println!("addr_buff: {}", format_array_as_hex_string(&addr_buff));

    println!("addr_buff[8..24]: {}", format_array_as_hex_string(&addr_buff[8..24]));
    let res: Result<[u8;16], TryFromSliceError > = addr_buff[8..24].try_into();
    let ipv6_dst: std::net::Ipv6Addr = match res {
      Ok(b) => std::net::Ipv6Addr::from(b),
      Err(e) => return Result::Err("failed to get ip scr".to_string() ),
    }; 
    println!("addr_buff[2..4]: {}", format_array_as_hex_string(&addr_buff[2..4]));
    let port_dst = match addr_buff[2..4].try_into() {
      Ok(b) => u16::from_le_bytes(b),
      Err(e) => return Result::Err("failed to get scr port".to_string() ),
    };
    println!("addr_buff[4..8]: {}", format_array_as_hex_string(&addr_buff[4..8]));
    let flow_dst = match addr_buff[4..8].try_into() {
      Ok(b) => u32::from_ne_bytes(b),
      Err(e) => return Result::Err("failed to get scr flow".to_string() ),
    };
    println!("addr_buff[24..28]: {}", format_array_as_hex_string(&addr_buff[24..28]));
    let scope_dst = match addr_buff[24..28].try_into() {
      Ok(b) => u32::from_ne_bytes(b),
      Err(e) => return Result::Err("failed to get scr scope".to_string() ),
    };

   
    let ipv6_sock_dst: SocketAddrV6 = SocketAddrV6::new(ipv6_dst, port_dst, flow_dst, scope_dst);

    println!("dst = {}", ipv6_sock_dst);
   
    let _size: usize = FillReflectedPacket( &recv_buff, &mut send_buff, hl, tv);
    let mut sended = 0;
    udp_sock.set_ttl(255);
    while sended < _size {
      match udp_sock.send_to(&send_buff[sended.._size-sended], ipv6_sock_dst ) {
        Ok(count) => sended += count,
        Err( error )=> return Result::Err(error.to_string()),
      };
    }
  }

  Result::Ok(())   
}

unsafe fn LibcSocketServer(tc: i32) {
  println!("LibcSocket");
  let sock = nix::sys::socket::socket( AddressFamily::Inet6, SockType::Datagram, SockFlag::empty(), Some(SockProtocol::Udp) ).unwrap();
  println!("Socket created {}. Setting options", sock );
  
  let addr: std::net::Ipv6Addr = std::net::Ipv6Addr::LOCALHOST;//std::net::Ipv6Addr::from_str("").unwrap();
  let b = SockaddrIn6::from( SocketAddrV6::new(addr, 9999, 0, 0) );
  let f = b.family().unwrap();
  println!("bind ip = {} port = {} family = {}", b.ip(), b.port(), f as u32 );
  match nix::sys::socket::bind(sock, &b) { //&sockaddr) {
    Ok(()) => println!("binded"),
    Err(err) => {println!("error: {}", err); return;},
  };

  nix::sys::socket::setsockopt(sock, sockopt::ReceiveTimestamp, &true).unwrap();
  nix::sys::socket::setsockopt(sock, sockopt::Ipv6TClass, &tc).unwrap();
  nix::sys::socket::setsockopt(sock, sockopt::Ipv6Ttl, &255).unwrap();
  
  let mut yes: [u8;4] = [0,0,0,1];
  let mut r = setsockopt(sock, nix::libc::IPPROTO_IPV6, nix::libc::IPV6_RECVHOPLIMIT, yes.as_mut_ptr() as *const c_void, 4 );
  println!("sockopt IPV6_RECVHOPLIMIT r {}", r);
  println!("{} {} {} {}", yes[0], yes[1], yes[2], yes[3]);
  r = setsockopt(sock, nix::libc::IPPROTO_IPV6, nix::libc::IPV6_RECVTCLASS, yes.as_mut_ptr() as *const c_void, 4);
  println!("sockopt IPV6_RECVTCLASS r {}", r);
 
  let mut addr_buff: [u8;16] = [0u8;16];
  let mut recv_buff: [u8;2048] = [0u8;2048];
  let mut control_buff: [u8;2048] = [0u8;2048];
    
  loop {
    let mut io_vec: iovec = iovec { iov_base: (recv_buff.as_mut_ptr() as *mut c_void), iov_len: (2048) };
    let mut message: msghdr = msghdr { msg_name: addr_buff.as_mut_ptr() as *mut c_void, msg_namelen: (16), msg_iov: (&mut io_vec), msg_iovlen: (1), msg_control: (control_buff.as_mut_ptr() as *mut c_void), msg_controllen: (2048), msg_flags: (0) };
   
    println!("recvmsg calling");
    let recved = nix::libc::recvmsg( sock, &mut message, 0); 
    println!("recved: {} message cl {} flags {}", recved, message.msg_controllen, message.msg_flags);
    if recved < 0 {
     return;
    }

    let mut data: *mut u8;
    //println!( "call first hdr" );
    let mut c_hdr_ref = CMSG_FIRSTHDR(/*msgref*/ &message as *const _);  
    while !c_hdr_ref.is_null() {
      println!("cmsg_level: {}, cmag_type: {}", (*c_hdr_ref).cmsg_level, (*c_hdr_ref).cmsg_type);
      data = CMSG_DATA(c_hdr_ref);
     // println!( "data: {}", format_array_as_hex_string((*data) );
      match ((*c_hdr_ref).cmsg_level, (*c_hdr_ref).cmsg_type) {      
        (nix::libc::IPPROTO_IPV6, nix::libc::IPV6_HOPLIMIT) => {
          let hl: i32 = ptr::read_unaligned(data as *const _);
          println!("hl = {}", hl);
        },
        (nix::libc::IPPROTO_IPV6, nix::libc::IPV6_TCLASS) => {
          let tc: i32 = ptr::read_unaligned(data as *const _);
          println!("tc = {}", tc);
        },
        (SOL_SOCKET, SCM_TIMESTAMP) => {
          let tv: nix::libc::timeval = ptr::read_unaligned(data as *const _);
          println!("tv = {} + {}", tv.tv_sec, tv.tv_usec);
        },
        (_, _) => {
          println!("unknown cmsg_level: {}, cmag_type: {}", (*c_hdr_ref).cmsg_level, (*c_hdr_ref).cmsg_type); 
        },
      }
      c_hdr_ref = CMSG_NXTHDR(&message as *const _, c_hdr_ref);
    }
  }

}


//IP.TTL IPv6.HopLimit -> 255 при отправке

/*

CONFIGURE Protocol
Request-TW-Session 
(Conf-Sender = 0, Conf-Receiver = 0, Number of Scheduled Slots and Number of Packets MUST be set to 0)
Sender Port  the Session-Sender will use the same UDP port to send and receive packets
Receiver Port is the desired UDP port to which TWAMP-Test packets will be sent by the Session-Sender
The Sender Address and Receiver Address fields contain, respectively,
   the sender and receiver addresses of the endpoints of the Internet
   path over which a TWAMP-Test session is requested.  They MAY be set
   to 0, in which case the IP addresses used for the Control-Client to
   Server TWAMP-Control message exchange MUST be used in the test
   packets.
Timeout is the interval that the Session-
   Reflector MUST wait after receiving a Stop-Sessions message.
Type-P descriptor is as defined in OWAMP [RFC4656].  The only
   capability of this field is to set the Differentiated Services Code
   Point (DSCP) as defined in [RFC2474].  The same value of DSCP MUST be
   used in test packets reflected by the Session-Reflector.
   0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |      1        |  MBZ  | IPVN  |  Conf-Sender  | Conf-Receiver |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                  Number of Schedule Slots                     |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                      Number of Packets                        |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |          Sender Port          |         Receiver Port         |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                        Sender Address                         |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     |           Sender Address (cont.) or MBZ (12 octets)           |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                        Receiver Address                       |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     |           Receiver Address (cont.) or MBZ (12 octets)         |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     |                        SID (16 octets)                        |
     |                                                               |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                         Padding Length                        |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                           Start Time                          |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                       Timeout, (8 octets)                     |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                       Type-P Descriptor                       |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                         MBZ (8 octets)                        |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     |                       HMAC (16 octets)                        |
     |                                                               |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Accept-Session message:
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |    Accept     |  MBZ          |            Port               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
     |                                                               |
     |                        SID (16 octets)                        |
     |                                                               |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     |                        MBZ (12 octets)                        |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     |                       HMAC (16 octets)                        |
     |                                                               |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      zero in the Accept field means that the server is
   willing to conduct the session.  A non-zero value indicates rejection
   of the request. 


Starting Test Sessions
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |      2        |                                               |
     +-+-+-+-+-+-+-+-+                                               |
     |                        MBZ (15 octets)                        |
     |                                                               |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     |                       HMAC (16 octets)                        |
     |                                                               |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
Start-Ack message
  0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |     Accept    |                                               |
     +-+-+-+-+-+-+-+-+                                               |
     |                        MBZ (15 octets)                        |
     |                                                               |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     |                       HMAC (16 octets)                        |
     |                                                               |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Stop-Sessions
0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |      3        |    Accept     |              MBZ              |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                      Number of Sessions                       |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                        MBZ (8 octets)                         |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
     |                                                               |
     |                        SID (16 octets)                        |
     |                                                               |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                           Next Seqno                          |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                     Number of Skip Ranges                     |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+



TEST Protocol
SessionSender UDP
  For unauthenticated mode:
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                        Sequence Number                        |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                          Timestamp                            |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |        Error Estimate         |                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
     |                                                               |
     .                                                               .
     .                         Packet Padding                        .
     .                                                               .
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  
  For authenticated and encrypted modes:
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                        Sequence Number                        |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     |                        MBZ (12 octets)                        |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                          Timestamp                            |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |        Error Estimate         |                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
     |                         MBZ (6 octets)                        |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     |                       HMAC (16 octets)                        |
     |                                                               |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               |
     .                                                               .
     .                        Packet Padding                         .
     .                                                               .
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  
  1) Sequence numbers start with zero and are incremented by one for each
  subsequent packet.

  2) Timestamp is represented as follows:
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                   Integer part of seconds                     |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                 Fractional part of seconds                    |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  void timeval_to_timestamp(const struct timeval *tv, TWAMPTimestamp * ts)
  {
    if (!tv || !ts)
        return;

    /* Unix time to NTP */
    ts->integer = tv->tv_sec + 2208988800uL;
    ts->fractional = (uint32_t) ((double)tv->tv_usec * ((double)(1uLL << 32)
                                                        / (double)1e6));

    ts->integer = htonl(ts->integer);
    ts->fractional = htonl(ts->fractional);
  }

  3) The Error Estimate specifies the estimate of the error and
   synchronization.  It has the following format:
         0                   1
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |S|Z|   Scale   |   Multiplier  |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  The first bit, S, SHOULD be set if the party generating the timestamp
   has a clock that is synchronized to UTC using an external source
   (e.g., the bit should be set if GPS hardware is used and it indicates
   that it has acquired current position and time or if NTP is used and
   it indicates that it has synchronized to an external source, which
   includes stratum 0 source, etc.).  If there is no notion of external
   synchronization for the time source, the bit SHOULD NOT be set.  The
   next bit has the same semantics as MBZ fields elsewhere: it MUST be
   set to zero by the sender and ignored by everyone else.  The next six
   bits, Scale, form an unsigned integer; Multiplier is an unsigned
   integer as well.  They are interpreted as follows: the error estimate
   is equal to Multiplier*2^(-32)*2^Scale (in seconds).  (Notation
   clarification: 2^Scale is two to the power of Scale.)  Multiplier
   MUST NOT be set to zero.  If Multiplier is zero, the packet SHOULD be
   considered corrupt and discarded.

SessionReflector UDP
  For unauthenticated mode:
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          Timestamp                            |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Error Estimate        |           MBZ                 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          Receive Timestamp                    |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sender Sequence Number                 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Sender Timestamp                         |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Sender Error Estimate    |           MBZ                 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Sender TTL   |                                               |
   +-+-+-+-+-+-+-+-+                                               +
   |                                                               |
   .                                                               .
   .                         Packet Padding                        .
   .                                                               .
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  For authenticated and encrypted modes:

   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        MBZ (12 octets)                        |
   |                                                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          Timestamp                            |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Error Estimate        |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
   |                        MBZ (6 octets)                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Receive Timestamp                      |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        MBZ (8 octets)                         |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sender Sequence Number                 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        MBZ (12 octets)                        |
   |                                                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Sender Timestamp                         |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Sender Error Estimate    |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
   |                        MBZ (6 octets)                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Sender TTL   |                                               |
   +-+-+-+-+-+-+-+-+                                               +
   |                                                               |
   |                                                               |
   |                        MBZ (15 octets)                        |
   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
   |                        HMAC (16 octets)                       |
   |                                                               |
   |                                                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
   |                                                               |
   .                                                               .
   .                         Packet Padding                        .
   .                                                               .
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
*/

const TwampPort: u16 = 862;
const REFWAIT:u32 = 900;

pub struct TwampSenders {
  senders: Vec<net::UdpSocket>,
}
impl TwampSenders {
  pub fn new() -> TwampSenders {
    TwampSenders {
      senders : Vec::new(),
    }
  }
}

pub struct TwampReflector {
  ip_addr : net::Ipv6Addr,
  ip_port: net::SocketAddrV6,
  socket: net::UdpSocket,
  max_clients: i16,
  work: bool,
}

impl TwampReflector {
 
  pub fn new( addr: Option<String>, port: Option<u16>, max: Option<i16> ) -> Result< TwampReflector, String> {
    let ip = match addr {
        Some(str) => {
          match net::Ipv6Addr::from_str(&str) {
            Ok(ip_addr) => ip_addr,
            Err(error) => return Result::Err(error.to_string()),
          }
        }
        None => net::Ipv6Addr::UNSPECIFIED,
    };
     
    let ip_port = match port {
        Some( number ) => net::SocketAddrV6::new(ip, number, 0, 0),
        None => net::SocketAddrV6::new(ip, TwampPort, 0, 0)
    };
    
    let sock = match net::UdpSocket::bind( ip_port ) {
        Ok(sock) => sock,
        Err( error) => return Result::Err(error.to_string()),           
    };    

    Result::Ok(TwampReflector { ip_addr: ip, ip_port: ip_port, socket: sock, max_clients: max.unwrap_or(-1), work: true })
  }

}

const sended_offset:usize = 24;

fn twamp_parse_udp_packet( recv_buffer: &[u8], send_buffer: &mut [u8], recv_count: usize ) {
 // send_buffer[sended_offset..sended_offset + 8].copy_from_slice(recv_buffer[]);  
}


fn twamp_read( sock: &mut UdpSocket) -> Result<u32, String>{
  let mut recv_buf: [u8;1024] = [0u8;1024];
  let mut send_buf: [u8;1024] = [0u8;1024];

  loop {
    let (_size, addr) = match sock.recv_from(&mut recv_buf) {
      Ok((s,a)) => (s,a),
      Err(err) => return Result::Err(err.to_string()),
    };

//socket.as_fd()


    twamp_parse_udp_packet( &recv_buf, &mut send_buf, _size);
    
    //socket.send_to(&send_buf, addr);
    let mut sended = 0;
    sock.set_ttl(255);
    while sended < _size {
      match sock.send_to(&send_buf[sended.._size-sended], addr ) {
        Ok(count) => sended += count,
        Err( error )=> return Result::Err(error.to_string()),
      };
    }    
  }

  Result::Ok(0)
}

fn twamp_client(port: &u16) {
  let server_addr: net::Ipv6Addr = net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
  println!("client created IPv6 {}", server_addr.to_string() );
  let server_sock_addr: net::SocketAddrV6 = net::SocketAddrV6::new( server_addr, *port, 0, 0);
  let sock: net::UdpSocket = match net::UdpSocket::bind(server_sock_addr) {
    Ok(sock) => sock,
    Err(error) => panic!("Couldn't bind socket {}", error ),
  };

  let mut send_buf: [u8; 1024] = [0u8; 1024];
  let mut recv_buf: [u8; 1024] = [0u8; 1024];
  let mut twamp_packet_size: usize = 0;
  let mut sended: usize = 0;
  loop {
    //TWAMP PACKET PREPARATION
    sended = 0;
    while sended < twamp_packet_size {
      match sock.send(&send_buf[sended..twamp_packet_size-sended]) {
        Ok(count) => sended += count,
        Err( error )=> {println!("send error {}", error); 
                               break},
      };
    }
    if sended < twamp_packet_size {
      break;
    }
    match sock.recv( &mut recv_buf){
      Ok(recved) => { println!("recved {}", recved );
                             //TWAMP PACKET PARSING
                           },
      Err(error) => { println!( "error recving {}", error);
                             break},
    };
  }
}

fn format_array_as_hex_string(bs: &[u8]) -> String {
    let mut visible = String::new();
    for b in bs {
      write!( visible, "0x{:02x} ", b);
        //let part: Vec<u8> = escape_default(b).collect();
        //visible.push_str(str::from_utf8(&part).unwrap());
    }
    visible
}


fn main() {

  let mut port: u16 = 9999;
  let pport = &port;

  let listen_addr: net::Ipv6Addr = net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
  
  println!("created IPv6 {}", listen_addr.to_string() );

  let listen_sock_addr: net::SocketAddrV6 = net::SocketAddrV6::new(listen_addr, port, 0, 0);
  
  println!("binding on UDP socket {}:{}", listen_addr.to_string(), pport );

  let listen_socket = match net::UdpSocket::bind(listen_sock_addr) {
    Ok(sock) => sock,
    Err(error) => panic!("Couldn't bind socket {}", error ),
  };

  println!("binded" );

  unsafe {
    TwampReflector( listen_socket, Some(3)).unwrap();
  }
  return;


  unsafe {
    LibcSocketServer(3);
  }
  return; 


  let args: Vec<String> = env::args().collect(); 
  for argument in args.iter() {   
    println!("arg: {}", argument);
  }

  
  let number: u32 = 100;
  let buff: [u8; 4] = number.to_le_bytes();
  let mut pckt: [u8; 128] = [0u8; 128];
  println!( "{}", format_array_as_hex_string(&pckt));
  pckt[12..16].copy_from_slice(&buff);
  println!( "{}", format_array_as_hex_string(&pckt));




  println!( "{}", format_array_as_hex_string(&buff));
  return;

  let mut packet: [u8; 1024] = [0u8; 1024];
  






  print!("new IPv6" );

  let mut port: u16 = 8892;
  let pport = &port;

  let listen_addr: net::Ipv6Addr = net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
  
  println!("created IPv6 {}", listen_addr.to_string() );

  let listen_sock_addr: net::SocketAddrV6 = net::SocketAddrV6::new(listen_addr, port, 0, 0);
  
  println!("binding on UDP socket {}:{}", listen_addr.to_string(), pport );

  let listen_socket = match net::UdpSocket::bind(listen_sock_addr) {
    Ok(sock) => sock,
    Err(error) => panic!("Couldn't bind socket {}", error ),
  };

  println!("binded" );
   
  let mut recv_buf = [0u8; 4096];
  
  loop {
    let (recved, client_src ) = match listen_socket.recv_from(&mut recv_buf) {
      Ok((size, addr)) => (size, addr),
      Err(error) => { 
                            println!("Couldn't recv from socket {}", error );
                            break;
                          },
    };
  
    println!( "recved = {}, from {}", recved, client_src );

    //TWAMP PARSING!!!!!!!!!!!!!!!!!

    let mut sended: usize = 0;
    while sended < recved {
      match listen_socket.send_to(&recv_buf[sended..recved], client_src) {
        Ok(size) => sended += size,
        Err(error) => {
                              println!("Couldn't send to socket {}", error );
                              break;
                            },
      }
    }
    if sended != recved {
     break;
    }
  }

  //twamp_senders.senders.push(listen_socket);

}










/*
fn read_message(socket: net::UdpSocket) -> Vec<u8> {
  let mut buf: [u8; 1] = [0; 1];
  println!("Reading data");
  let result = socket.recv_from(&mut buf);
  drop(socket);
  let data;
  match result {
    Ok((amt, src)) => {
      println!("Received data from {}", src);
      data = Vec::from(&buf[0..amt]);
    },
    Err(err) => panic!("Read error: {}", err)
  }
  data
}


pub fn send_message(send_addr: net::SocketAddr, target: net::SocketAddr, data: Vec<u8>) {
  let socket = socket(send_addr);
  println!("Sending data");
  let result = socket.send_to(&data, target);
  drop(socket);
  match result {
    Ok(amt) => println!("Sent {} bytes", amt),
    Err(err) => panic!("Write error: {}", err)
  }
}

pub fn listen(listen_on: net::SocketAddr) -> thread::JoinHandle<Vec<u8>> {
  let socket = socket(listen_on);
  let handle = thread::spawn(move || {
    read_message(socket)
  });
  handle
}

fn main() {
    println!("Hello, world!");
       println!("UDP");
    let ip = net::Ipv4Addr::new(127, 0, 0, 1);
    let listen_addr = net::SocketAddrV4::new(ip, 8888);
    let send_addr = net::SocketAddrV4::new(ip, 8889);
    let future = listen(net::SocketAddr::V4(listen_addr));
    let message: Vec<u8> = vec![10];
 // give the thread 3s to open the socket
    thread::sleep(Duration::new(3, 0 ));
    send_message(net::SocketAddr::V4(send_addr), net::SocketAddr::V4(listen_addr), message);
    println!("Waiting");
    let received = future.join().unwrap();
    println!("Got {} bytes", received.len());
    assert_eq!(1, received.len());
    assert_eq!(10, received[0]);
}




TCP

use std::io::{self, Write};
use std::net::TcpStream;

fn main() {
  let mut stream = TcpStream::connect("127.0.0.1:8080").expect("connect failed");

  loop {
    let mut input = String::new();
    let size = io::stdin().read_line(&mut input).expect("read line failed");

    stream
      .write(&input.as_bytes()[..size])
      .expect("write failed");
  }
}



use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::str;
use std::thread;

fn handle_client(mut stream: TcpStream) {
    let mut buf = [0; 128];
    loop {
        // Read the content
        let len = stream.read(&mut buf).unwrap();
        if len == 0 {
            println!("ok");
            break;
        }
                 / / Output read content
        println!("read {} bytes: {:?}", len, str::from_utf8(&buf[..len]));
    }
}

fn main() {
    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();

         / / Turn on each connection to process
    for stream in listener.incoming() {
        thread::spawn(move || {
            handle_client(stream.unwrap());
        });
    }
    println!("Hello, world!");
}


*/
