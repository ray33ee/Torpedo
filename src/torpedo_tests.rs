

#[cfg(test)]
mod torpedo_tests {
    use native_tls::{TlsConnector, Protocol};
    use std::net::{TcpStream, IpAddr, Ipv4Addr};
    use crate::cells::{TorCell, Command, RelayCell, Encrypted};
    use torserde::{NLengthVector, VersionsVector};
    use torserde::TorSerde;
    use chrono::Local;
    use std::str::FromStr;

    use crate::custom_crypto::kdf_tor;
    use crate::cellcrypto::CellCrypto;
    use std::convert::TryInto;

    #[test]
    fn test_cells_coms() {
        let connector = TlsConnector::builder()
            .danger_accept_invalid_hostnames(true)
            .danger_accept_invalid_certs(true)
            .min_protocol_version(Some(Protocol::Tlsv12))
            .build().unwrap();

        let stream = TcpStream::connect("100.16.224.136:8080").unwrap();
        let mut stream = connector.connect("", stream).unwrap();

        TorCell::new(0, Command::Versions {version_list: VersionsVector::from(vec![3, 4]) }).into_stream(& mut stream, 3);

        let versions = TorCell::from_stream(& mut stream, 3);

        println!("{:?}", versions);

        let certs = TorCell::from_stream(& mut stream, 4);

        println!("{:?}", certs);

        let auth = TorCell::from_stream(& mut stream, 4);

        println!("{:?}", auth);

        let netinfo = TorCell::from_stream(& mut stream, 4);

        println!("{:?}", netinfo);

        TorCell::new(0, Command::NetInfo {
            timestamp: Local::now(),
            other_ip: IpAddr::V4(Ipv4Addr::from_str("100.16.224.136").unwrap()),
            this_ips: NLengthVector::from(vec![IpAddr::V4(Ipv4Addr::from_str("0.0.0.0").unwrap())]) }).into_stream(& mut stream, 4);

        let half_handshake = [3u8; 20];

        TorCell::new(0x80000001, Command::CreateFast {onion_skin: half_handshake}).into_stream(& mut stream, 4);

        let created_fast = TorCell::from_stream(& mut stream, 4);

        println!("{:?}", created_fast);

        if let Command::CreatedFast{ handshake_data } = created_fast.get_command() {

            //Generate and obtain shared secrets

            let mut shared_secret = Vec::from([3u8; 20]);

            shared_secret.extend_from_slice(&handshake_data[0..20]);

            println!("secret: {:?}", shared_secret);

            let materials = kdf_tor(&shared_secret);

            let mut cell_crypto = CellCrypto::from(&materials[20..92].try_into().unwrap());

            //Send cells

            let mut relay_begin_dir = RelayCell::new(1, crate::cells::Relay::BeginDir);

            cell_crypto.set_forward_digest(& mut relay_begin_dir);

            let encrypted_begin = cell_crypto.encrypt(relay_begin_dir);

            let relay_begin = TorCell::new(0x80000001, Command::Relay { contents: encrypted_begin });

            relay_begin.into_stream(& mut stream, 4);

            //Read cell

            let begun = TorCell::from_stream(& mut stream, 4);

            println!("cell data: {:?}", begun);

            if let crate::cells::Command::Relay { contents } = begun.get_command() {
                let mut contents = cell_crypto.decrypt(contents.clone());

                println!("decrypted: {:?}", contents);

                let digest_result = cell_crypto.verify_backward_digest(& mut contents);

                assert!(digest_result);

                println!("Verifyt: {}", digest_result);
            }


        }




    }

    #[test]
    fn test_kdf_tor() {
        use crate::custom_crypto::kdf_tor;

        let secret = [120u8, 177, 253, 48, 253, 132, 68, 100, 0, 13, 186, 177, 249, 202, 249, 125, 25, 170, 184, 108, 70, 232, 121, 233, 100, 6, 158, 233, 138, 146, 107, 137, 220, 35, 116, 88, 176, 221, 248, 163, ];

        kdf_tor(&secret);

    }

    #[test]
    fn test_cell_crypto() {



        let key_materials: [u8; 72] = [44, 102, 210, 192, 76, 172, 8, 173, 133, 217, 207, 18, 129, 148, 34, 186, 219, 97, 121, 226, 167, 46, 22, 191, 124, 86, 64, 116, 90, 33, 94, 66, 220, 175, 77, 207, 126, 245, 190, 175, 93, 187, 116, 16, 2, 169, 37, 146, 211, 13, 242, 210, 79, 237, 174, 147, 43, 8, 58, 20, 144, 50, 192, 237, 0, 68, 185, 81, 204, 103, 69, 93];

        let mut crypto_cell = CellCrypto::from(&key_materials);

        let mut data = [0u8; 509];

        let mut cell = RelayCell::new(1, crate::cells::Relay::BeginDir);

        cell.bin_serialise_into(data.as_mut());

        println!("relay testing: {:?}", data);

        crypto_cell.set_forward_digest(& mut cell);
        println!("digest {}", cell.get_digest());

        cell.bin_serialise_into(data.as_mut());

        println!("WITH DIGEST: {:?}", data);

        let encrypted = crypto_cell.encrypt(cell);

        println!("ENCRYPTED: {:?}", encrypted.0);

    }

    #[test]
    fn second_cellcrypto() {
        let key_materials: [u8; 72] = [44, 102, 210, 192, 76, 172, 8, 173, 133, 217, 207, 18, 129, 148, 34, 186, 219, 97, 121, 226, 167, 46, 22, 191, 124, 86, 64, 116, 90, 33, 94, 66, 220, 175, 77, 207, 126, 245, 190, 175, 93, 187, 116, 16, 2, 169, 37, 146, 211, 13, 242, 210, 79, 237, 174, 147, 43, 8, 58, 20, 144, 50, 192, 237, 0, 68, 185, 81, 204, 103, 69, 93];

        let mut crypto_cell = CellCrypto::from(&key_materials);

        let encrypted = Encrypted([149, 240, 30, 56, 185, 14, 138, 9, 191, 248, 201, 17, 121, 247, 106, 134, 21, 106, 132, 107, 145, 150, 202, 152, 104, 51, 100, 164, 58, 84, 121, 103, 41, 97, 220, 17, 244, 107, 131, 1, 254, 116, 82, 149, 13, 62, 29, 72, 64, 192, 49, 75, 245, 161, 35, 27, 221, 12, 41, 145, 248, 59, 156, 176, 181, 70, 230, 152, 242, 95, 105, 154, 67, 36, 160, 107, 187, 64, 124, 76, 229, 195, 142, 25, 133, 77, 75, 171, 199, 108, 247, 226, 119, 226, 214, 169, 99, 211, 131, 36, 86, 234, 146, 53, 241, 139, 145, 251, 153, 198, 15, 255, 217, 210, 2, 105, 246, 83, 226, 30, 177, 148, 2, 228, 208, 193, 131, 199, 225, 239, 176, 80, 113, 120, 122, 51, 174, 23, 38, 159, 83, 161, 13, 102, 70, 30, 189, 56, 71, 58, 202, 217, 167, 97, 172, 145, 15, 166, 218, 190, 90, 125, 134, 171, 153, 39, 165, 44, 206, 226, 141, 147, 234, 55, 237, 103, 250, 160, 60, 252, 130, 51, 92, 146, 208, 181, 42, 121, 122, 133, 189, 60, 231, 152, 237, 224, 55, 210, 223, 238, 63, 45, 94, 98, 248, 237, 12, 174, 149, 91, 133, 125, 45, 55, 23, 46, 81, 213, 181, 228, 70, 54, 222, 152, 214, 180, 50, 192, 162, 240, 22, 241, 242, 118, 16, 140, 102, 80, 204, 44, 220, 205, 56, 111, 216, 83, 7, 217, 88, 119, 194, 173, 30, 9, 193, 74, 68, 213, 237, 224, 201, 202, 201, 80, 52, 69, 9, 118, 176, 105, 24, 227, 156, 206, 114, 165, 46, 200, 120, 30, 152, 71, 64, 2, 60, 65, 68, 223, 127, 248, 131, 7, 137, 0, 61, 76, 156, 224, 91, 137, 108, 87, 13, 203, 14, 143, 205, 68, 210, 176, 70, 30, 45, 9, 235, 112, 58, 41, 145, 204, 65, 86, 228, 148, 94, 234, 121, 73, 170, 161, 141, 162, 13, 57, 38, 61, 232, 80, 224, 103, 103, 132, 165, 62, 53, 116, 197, 210, 195, 116, 141, 125, 57, 231, 107, 216, 133, 255, 28, 38, 172, 7, 150, 200, 66, 120, 158, 29, 199, 25, 107, 134, 79, 77, 108, 230, 138, 48, 249, 120, 59, 245, 209, 179, 8, 180, 33, 93, 54, 99, 27, 180, 3, 255, 246, 248, 230, 208, 138, 128, 133, 227, 252, 87, 141, 124, 141, 77, 57, 186, 72, 61, 143, 170, 78, 77, 37, 45, 43, 170, 8, 160, 126, 52, 133, 175, 12, 105, 236, 96, 38, 20, 20, 57, 83, 137, 9, 58, 180, 183, 113, 255, 251, 250, 180, 152, 130, 255, 81, 235, 99, 217, 129, 17, 185, 193, 124, 49, 219, 219, 111, 80, 195, 22, 219, 137, 122, 215, 251, 63, 253, 81, 35, 110, 122, 3, 110, 206, 19, 185, 39, 89, 42, 255, 226, 171, 63, 13, 16, 202, 109, 57, 15, 179, 175, 133, 101, 33, 237, 6, 24, 13, 200, 180, 35, 228, 56, 194, 123]);

        let mut cell = crypto_cell.decrypt(encrypted);

        println!("Decrypted: {:?}", cell);

        println!("digested: {:?}", crypto_cell.verify_backward_digest(& mut cell));


    }

    #[test]
    fn test_mirror_dirs() {
    }

}