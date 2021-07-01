
use sha1::Sha1;
use sha1::Digest;
use std::io::Write;

use ctr::cipher::{NewCipher, StreamCipher};
use std::convert::TryInto;
use crate::cells::{RelayCell, Encrypted};
use torserde::TorSerde;

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

        forward_digest.write(f_digest).unwrap();
        backward_digest.write(b_digest).unwrap();

        //Tor uses an inialisation vector of all zeros in its SHA1 hashes
        let iv = 0u128.to_be_bytes();

        let forward_encryptor = Aes128Ctr::new(f_key.into(), iv.as_ref().into());
        let backward_decryptor = Aes128Ctr::new(b_key.into(), iv.as_ref().into());

        println!("fkey: {:?}", f_key);

        Self {
            forward_digest,
            backward_digest,
            forward_encryptor,
            backward_decryptor,
        }

    }

    pub fn set_forward_digest(& mut self, relay: & mut RelayCell) -> torserde::Result<()> {

        relay.bin_serialise_into(& mut self.forward_digest)?;

        let clone = self.forward_digest.clone();

        let digest = clone.finalize();

        relay.set_digest(u32::from_be_bytes(digest[0..4].try_into().unwrap()));

        Ok(())
    }

    pub fn verify_backward_digest(& mut self, relay: & mut RelayCell) -> torserde::Result<()> {

        let sent_digest = relay.get_digest();

        relay.set_digest(0);

        let mut test = [0u8; 509];

        relay.bin_serialise_into(test.as_mut())?;

        println!("test@ {:?}", test);

        relay.bin_serialise_into(& mut self.backward_digest)?;

        let clone = self.backward_digest.clone();

        let calculated_digest = u32::from_be_bytes((&clone.finalize()[0..4]).try_into().unwrap());

        println!("calculated: {}", calculated_digest);

        if sent_digest != calculated_digest {
            return Err(torserde::ErrorKind::BadDigest(sent_digest, calculated_digest));
        }

        Ok(())
    }

    pub fn encrypt(& mut self, relay: RelayCell) -> torserde::Result<Encrypted> {

        let mut array = [0u8; 509];

        relay.bin_serialise_into(array.as_mut())?;

        self.forward_encryptor.apply_keystream(array.as_mut());

        Ok(Encrypted(array))

    }

    pub fn decrypt(& mut self, relay: Encrypted) -> torserde::Result<RelayCell> {

        let mut array = relay.0;

        self.backward_decryptor.apply_keystream(array.as_mut());

        RelayCell::bin_deserialise_from(array.as_ref())
    }
}