
use std::net::{IpAddr, Ipv4Addr};
use chrono::{DateTime, Local};

use torserde_macros::Torserde;
use torserde::{TorSerde, NLengthVector, VersionsVector};
use std::io::{Read, Write};
use std::borrow::{BorrowMut};

use lazy_static::lazy_static;
use ring::rand::SecureRandom;

lazy_static!{
    static ref CSRNG: ring::rand::SystemRandom = ring::rand::SystemRandom::new();
}

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
pub enum SendMePayload {
    Ignore = 0,
    Authenticated { length: u16, digest: [u8; 20] } = 1,
}

//Represents the payload of an encrypted cell
#[derive(Debug, Clone, Torserde)]
pub struct Encrypted(pub [u8; 509]);

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
    SendMe { payload: SendMePayload } = 5, //Done

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
    Create{ onion_skin: [u8; 20] } = 1, //Done
    //Created = 2,
    Relay{ contents: Encrypted } = 3, //Figure out padding and encryption
    Destroy{ reason: DestroyReason } = 4, //Done
    CreateFast{ onion_skin: [u8; 20] } = 5, //Done
    CreatedFast{ handshake_data: [u8; 40] } = 6, //Done
    NetInfo{ timestamp: DateTime<Local>, other_ip: IpAddr, this_ips: NLengthVector<IpAddr, 1> } = 8, //Done
    RelayEarly{ contents: Encrypted } = 9, //Figure out padding and encryption
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

#[derive(Debug, Clone)]
pub struct RelayCell {
    command: u8,
    recognised: u16,
    stream_id: u16,
    digest: u32,
    data: NLengthVector<u8, 2>,
    padding: Option<Vec<u8>>,


}

impl TorSerde for RelayCell {
    fn bin_serialise_into<W: Write>(&self, mut stream: W) -> u32 {
        self.command.bin_serialise_into(stream.borrow_mut());
        self.recognised.bin_serialise_into(stream.borrow_mut());

        self.stream_id.bin_serialise_into(stream.borrow_mut());

        self.digest.bin_serialise_into(stream.borrow_mut());

        self.data.bin_serialise_into(stream.borrow_mut());

        std::io::copy(& mut (&self.padding.as_ref().unwrap()[..]), stream.borrow_mut()).unwrap();

        509
    }

    fn bin_deserialise_from<R: Read>(mut stream: R) -> Self {
        let command = u8::bin_deserialise_from(stream.borrow_mut());
        let recognised = u16::bin_deserialise_from(stream.borrow_mut());
        let stream_id = u16::bin_deserialise_from(stream.borrow_mut());
        let digest = u32::bin_deserialise_from(stream.borrow_mut());
        let data = <NLengthVector<u8, 2>>::bin_deserialise_from(stream.borrow_mut());

        let mut taken = stream.borrow_mut().take((509 - 11 - data.0.len()) as u64);

        let mut padding = Vec::new();

        taken.read_to_end(& mut padding).unwrap();

        let padding = Some(padding);

        Self {
            command,
            recognised,
            stream_id,
            digest,
            data,
            padding,
        }
    }

    fn serialised_length(&self) -> u32 {
        509
    }
}

impl RelayCell {

    pub fn new(stream_id: u16, contents: Relay) -> Self {
        let recognised = 0;
        let digest = 0;
        let (command, data) = Self::get_vector(contents);

        let mut padding: Vec<_> = (0..509-11-data.0.len()).into_iter().map(|_| 0u8).collect();

        CSRNG.fill(& mut padding).unwrap();

        let padding = Some(padding);

        Self {
            command,
            recognised,
            stream_id,
            digest,
            data,
            padding,
        }
    }

    pub fn set_digest(& mut self, digest: u32) {
        self.digest = digest;
    }

    pub fn get_digest(& self) -> u32 {
        self.digest
    }

    fn get_vector(relay: Relay) -> (u8, NLengthVector<u8, 2>) {
        let mut data = Vec::new();
        //Todo: Create a special object that implements write, that returns the discriminant followed by the data without having to remove from a vector

        relay.bin_serialise_into(& mut data);

        let command = data.remove(0);

        (command, NLengthVector::from(data))
    }

    fn get_relay(&self) -> Option<Relay> {

        if self.data.0.is_empty() {
            None
        } else {
            let mut data = self.data.0.clone();

            data.insert(0, self.command);

            //Todo: Create a special object that implements read, that returns the discriminant followed by the data without having to prepend a vector

            //Now data contains a discriminant followed by a list of data.
            //This is exactly what we need to describe an enum

            Some(Relay::bin_deserialise_from(data.as_slice()))
        }

    }



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

    pub fn get_command(& self) -> &Command {
        &self.payload
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
            (self.circuit_id as u16).bin_serialise_into(stream.borrow_mut());
        } else {
            (self.circuit_id as u32).bin_serialise_into(stream.borrow_mut());
        }

        self.payload.bin_serialise_into(stream.borrow_mut()); //Subtract one since out payload includes the command byte

        if !self.payload.is_var_len() {
            for _ in 0..(510-self.payload.serialised_length()) {
                0u8.bin_serialise_into(stream.borrow_mut());
            }
        }

    }

}