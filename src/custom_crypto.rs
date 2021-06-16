
use sha1::Sha1;
use sha1::Digest;
use std::io::Write;
use sha1::digest::Reset;

pub fn kdf_tor(shared_secret: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();

    let mut key_stuff = Vec::new();

    for i in 0..5 {

        hasher.write(shared_secret).unwrap();
        hasher.write(&[i]).unwrap();

        key_stuff.extend_from_slice(&hasher.clone().finalize());
        Reset::reset(&mut hasher);

    }

    key_stuff.truncate(92);

    key_stuff
}