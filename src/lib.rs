#![feature(arbitrary_enum_discriminant)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use chrono::{DateTime, Local};

use torserde_macros::Torserde;
use torserde::{TorSerde, NLengthVector, VersionsVector};
use std::io::{Read, Write};
use std::borrow::BorrowMut;

//mod macro_tests;
mod torpedo_tests;
mod macro_tests;

#[derive(Debug, Clone, Torserde)]
pub struct Cert {
    cert_type: u8,
    certificate: NLengthVector<u8, 2>,
}

#[derive(Debug, Clone, Torserde)]
pub struct LinkSpecifier {
    ltype: u8,
    lspec: NLengthVector<u8, 1>
}

#[derive(Debug, Clone, Torserde)]
#[repr(u8)]
pub enum EndReason {
    Misc = 1,
    ResolveFailed = 2,
    ConnectRefused = 3,
    ExitPolicy{ ip: Ipv4Addr, ttl: u32 } = 4,
    Destroy = 5,
    Done = 6,
    Timeout = 7,
    NoRoute = 8,
    Hibernating = 9,
    Internal = 10,
    ResourceLimit = 11,
    ConnReset = 12,
    TorProtocol = 13,
    NotDirectory = 14,
}

#[derive(Debug, Clone, Torserde)]
#[repr(u8)]
pub enum DestroyReason {
    None = 0,
    Protocol = 1,
    Internal = 2,
    Requested = 3,
    Hibernating = 4,
    ResourceLimit = 5,
    ConnectFailed = 6,
    OrIdentity = 7,
    OrConnClosed = 8,
    Finished = 9,
    Timeout = 10,
    Destroyed = 11,
    NoSuchService = 12,

}

#[derive(Debug, Clone, Torserde)]
#[repr(u8)]
pub enum Relay {
    Begin{ addr_and_port: String, flags: u32 } = 1, //Done
    Data{ data: [u8; 498] } = 2, //DOne - Be careful with this as moving [u8; 498] is expensive
    End{ end_reason: EndReason } = 3, //Done
    Connected { ip: Ipv4Addr, ttl: u32 } = 4, //Done
    SendMe { version: u8, digest: NLengthVector<u8, 2> } = 5, //Done

    Truncated{ reason: DestroyReason } = 9, //Done

    BeginDir = 13,
    Extend2{ link_specifiers: NLengthVector<LinkSpecifier, 1>, htype: u16, handshake_data: NLengthVector<u8, 2> } = 14, //What is a link specifier?
    Extended2{ handshake_data: NLengthVector<u8, 2> } = 15, //Done
    EstablishRendezvous{ rendezvous_cookie: [u8; 20] } = 33, //Done
    Introduce1 = 34, //Need to do this one
    // Rendezvous2{ handshake_data: & 'a [u8] } = 37, // Length?
    RendezvousEstablished = 39,
    IntroduceAck = 40,
}

#[derive(Debug, Clone, Torserde)]
#[repr(u8)]
pub enum Command {
    /* Fixed length commands */
    Padding = 0,
    Create{ onion_skin: [u8; 186] } = 1, //Done
    //Created = 2,
    Relay{ send_relay: Relay, stream_id: u16, padding: NLengthVector<IpAddr, 1>, encrypted: u32 } = 3, //Figure out padding and encryption
    Destroy{ reason: DestroyReason } = 4, //Done
    CreateFast{ onion_skin: [u8; 186] } = 5, //Done
    CreatedFast{ handshake_data: [u8; 40] } = 6, //Done
    NetInfo{ timestamp: DateTime<Local>, other_ip: IpAddr, this_ips: NLengthVector<IpAddr, 1> } = 8, //Done
    RelayEarly{ send_relay: Relay, stream_id: u16, padding: NLengthVector<IpAddr, 1>, encrypted: u32 } = 9, //Figure out padding and encryption
    Create2{ handshake_type: u16, onion_skin: NLengthVector<u8, 2> } = 10, //Done
    Created2{ handshake_data: NLengthVector<u8, 2> } = 11, //Done

    /* Variable length commands */
    Versions{ version_list: VersionsVector } = 7, //Done
    //VPadding = 128,
    Certs{ length: u16, certs: NLengthVector<Cert, 1> } = 129, //Done
    AuthChallenge{ length: u16, challenge: [u8; 32], methods: NLengthVector<u16, 2> } = 130, //Done
    //Authenticate = 131,
    //Authorize = 132,
}

impl Command {

    fn is_var_len(&self) -> bool {
        match &self {
            Command::Versions { .. } => { true }
            Command::Certs { .. } => { true }
            Command::AuthChallenge { .. } => { true}
            _ => { false }
        }
    }
}

struct NullReader;

impl Write for NullReader {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        std::io::Result::Ok(0)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Result::Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct TorCell {
    circuit_id: u32,
    payload: Command, //Contains the command, length (optional) and payload
}

impl<'a> TorCell {
    pub fn new(circuit_id: u32, payload: Command) -> Self {

        Self {
            circuit_id,
            payload,
        }
    }

    pub fn from_stream<R: Read>(mut stream: R, version: u32) -> Self {
        let circuit_id = if version < 4 {
            u16::bin_deserialise_from(stream.borrow_mut()) as u32
        } else {
            u32::bin_deserialise_from(stream.borrow_mut())
        };

        let payload = Command::bin_deserialise_from(stream.borrow_mut());

        //If it's a fixed length command, we need to flush any padding from the stream
        if !payload.is_var_len() {
            let payload_length = payload.serialised_length() - 1; //Subtract one because the serialised length includes the payload AND the discriminant (which is one byte)

            let mut taken = stream.borrow_mut().take((509 - payload_length) as u64);

            std::io::copy(& mut taken, & mut NullReader);
        }

        Self {
            circuit_id,
            payload
        }
    }

    pub fn into_stream<W: Write>(self, mut stream: W, version: u32) {
        if version < 4 {
            (self.circuit_id as u16).bin_serialise_into(stream.borrow_mut())
        } else {
            (self.circuit_id as u32).bin_serialise_into(stream.borrow_mut())
        }

        self.payload.bin_serialise_into(stream.borrow_mut());

    }

}
