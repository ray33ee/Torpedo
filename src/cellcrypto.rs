
use sha1::Sha1;
use sha1::Digest;
use std::io::Write;

use ctr::cipher::{NewCipher, StreamCipher, StreamCipherSeek};
use std::convert::TryInto;

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

//An object to handle the forward encryption, backward decryption and verification of relay cells
pub struct CellCrypto {
    forward_digest: Sha1,
    backward_digest: Sha1,
    forward_encryptor: Aes128Ctr,
    backward_decryptor: Aes128Ctr,
}

impl From<&[u8; 72]> for CellCrypto {
    fn from(key_materials: &[u8; 72]) -> Self {
        Self::new(
            (&key_materials[0..20]).try_into().unwrap(),
            (&key_materials[20..40]).try_into().unwrap(),
            (&key_materials[40..56]).try_into().unwrap(),
            (&key_materials[56..72]).try_into().unwrap())
    }
}

impl CellCrypto {
    pub fn new(f_digest: &[u8; 20], b_digest: &[u8; 20], f_key: &[u8; 16], b_key: &[u8; 16]) -> Self {
        let mut forward_digest = Sha1::new();
        let mut backward_digest = Sha1::new();

        forward_digest.write(f_digest);
        backward_digest.write(b_digest);

        //Tor uses an inialisation vector of all zeros in its SHA1 hashes
        let iv = 0u128.to_be_bytes();

        let forward_encryptor = Aes128Ctr::new(f_key.into(), iv.as_ref().into());
        let backward_decryptor = Aes128Ctr::new(b_key.into(), iv.as_ref().into());

        Self {
            forward_digest,
            backward_digest,
            forward_encryptor,
            backward_decryptor,
        }

    }

    pub fn set_forward_digest(& mut self, data: & mut [u8]) {
        self.forward_digest.write(data);

        let clone = self.forward_digest.clone();

        let digest = clone.finalize();

        for (i, byte) in (&digest[0..4]).iter().enumerate() {
            data[5+i] = *byte;
        }
    }

    pub fn verify_backward_digest(& mut self, data: & mut [u8]) -> bool {

        let sent_digest = u32::from_be_bytes((&data[5..9]).try_into().unwrap());

        for byte in & mut data[5..9] {
            *byte = 0;
        }

        self.backward_digest.write(data);

        let clone = self.backward_digest.clone();

        let calculated_digest = u32::from_be_bytes((&clone.finalize()[0..4]).try_into().unwrap());

        sent_digest == calculated_digest
    }

    pub fn encrypt(& mut self, data: & mut [u8]) {
        self.forward_encryptor.apply_keystream(data);
    }

    pub fn decrypt(& mut self, data: & mut [u8]) {
        self.backward_decryptor.apply_keystream(data);
    }
}