

#[cfg(test)]
mod torpedo_tests {
    use native_tls::{TlsConnector, Protocol};
    use std::net::TcpStream;
    use std::io::{Write, Read};
    use crate::{TorCell, Command};
    use crate::EndReason::TorProtocol;
    use torserde::{NLengthVector, VersionsVector};
    use torserde::TorSerde;
    use crate::Command::Versions;

    #[test]
    fn test_cells_coms() {
        let connector = TlsConnector::builder()
            .danger_accept_invalid_hostnames(true)
            .danger_accept_invalid_certs(true)
            .min_protocol_version(Some(Protocol::Tlsv12))
            .build().unwrap();

        let stream = TcpStream::connect("163.172.179.31:9001").unwrap();
        let mut stream = connector.connect("", stream).unwrap();


        //stream.write_all(&[0, 0, 7, 0, 2, 0, 3, 0, 4]).unwrap();

        let mut buf = [0u8; 1000];

        //TorCell::new(0, 7, vec![0, 3, 0, 4]).into_stream(& mut stream, 3);

        //println!("{:?}", buf);

        TorCell::new(0, Command::Versions {version_list: VersionsVector::from(vec![3, 4]) }).into_stream(& mut stream, 3);

        //let buv: u8 = bincode::deserialize_from(& mut stream).unwrap();

        let versions = TorCell::from_stream(& mut stream, 3);

        println!("versions: {:?}", versions);

        //stream.read(& mut buf).unwrap();

        //println!("buf: {:?}", buf);

        let certs = TorCell::from_stream(& mut stream, 4);

        println!("cerrts: {:?}", certs);

        let auth = TorCell::from_stream(& mut stream, 4);

        println!("authL {:?}", auth);

        let netinfo = TorCell::from_stream(& mut stream, 4);

        println!("netinfo: {:?}", netinfo);

        let mut b = [0u8; 1];

        //stream.read(& mut b);


        //println!("buv: {:?}", buv);

        /*let versions = TorCell::from_stream(&mut stream, 3);
        println!("versions: {:?}", versions);

        let certs = TorCell::from_stream(&mut stream, 4);
        println!("certs: {:?}", certs);
        let auth = TorCell::from_stream(&mut stream, 4);
        println!("auth: {:?}", auth);
        let netinfo = TorCell::from_stream(&mut stream, 4);
        println!("netinfo: {:?}", netinfo);*/
    }
}