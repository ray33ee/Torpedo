use std::io::{Write, Read};
use std::io::Result;

/// A simple write stream that consumes bytes
pub struct NullStream;

impl Write for NullStream {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        std::io::Result::Ok(_buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Result::Ok(())
    }
}

/// A stream that serialises and deserialises a command/data pair
pub struct UnpackedCell {
    command: u8,
    data: Option<Vec<u8>>,
    written_command: bool,
    bytes_read: u64,
}

impl UnpackedCell {
    pub fn new(command: u8, data: Option<Vec<u8>>) -> Self {
        Self {
            command,
            data,
            written_command: false,
            bytes_read: 0,
        }
    }

    pub fn command(&self) -> u8 {
        self.command
    }

    pub fn data_length(&self) -> usize {
        self.data.as_ref().unwrap().len()
    }

    pub fn data(self) -> Vec<u8> {
        self.data.unwrap()
    }
}

impl Default for UnpackedCell {
    fn default() -> Self {
        Self::new(0, None)
    }
}

impl Write for UnpackedCell {
    fn write(&mut self, mut buf: &[u8]) -> Result<usize> {

        let mut bytes_written = 0;

        if self.data.is_none() {
            self.data = Some(Vec::with_capacity(509)); //Relay cells are max 509 bytes
        }

        if !self.written_command {
            self.command = *buf.get(0).unwrap();
            buf = &buf[1..];
            bytes_written += 1;
            self.written_command = true;
        }

        let vec_ref = self.data.as_mut().unwrap();

        vec_ref.extend_from_slice(buf);

        bytes_written += buf.len();

        Ok(bytes_written)
    }

    fn flush(&mut self) -> Result<()> {
        Result::Ok(())
    }
}

impl Read for UnpackedCell {
    fn read(&mut self, mut buf: &mut [u8]) -> Result<usize> {

        let mut bytes_read = 0;

        if self.data.is_none() {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "Unpacked cell contains no data"));
        }

        if self.bytes_read == 0 {
            let first_element = buf.get_mut(0).unwrap();
            *first_element = self.command;
            buf = & mut buf[1..];
            bytes_read += 1;
            self.bytes_read += 1;
            self.written_command = true;
        }

        let start = self.bytes_read as usize - 1;

        let vec_ref = self.data.as_ref().unwrap();

        let write_bytes = if start + buf.len() > vec_ref.len() { vec_ref.len() - start } else { buf.len() };

        buf.write_all(&vec_ref[start..start+write_bytes]).unwrap();

        bytes_read += write_bytes;

        self.bytes_read += write_bytes as u64;

        println!("read: {}", self.bytes_read);

        Ok(bytes_read)
    }
}
