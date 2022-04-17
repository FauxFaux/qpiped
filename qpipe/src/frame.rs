// all little endian

// FOURCC: [u8; 4]
// DATA_LENGTH: u16 (excludes header)

// e.g. "errm\0\7\0\0\0\1\2hi"
//           ^^^^ data length
//               ^^^^^^^^ error code
//                       ^^ message length
//                         ^^ message

// 'con1' - initiate connection
// tcp/udp: 't' | 'u'
// address_port_len: u8
// address_port: [u8; address_port_len] e.g. "example.com:80"
// [unspecified]

// 'okay'
// [unspecified]

// 'errm' - error with message
// code: u32,
// message_len: u8
// message: [u8; message_len]
// [unspecified]

// 'data' (len=0 is illegal?)
// [all user bytes]

// 'fini' - no more writes from my side
// [unspecified]

// 'ping'
// token: u64
// [unspecified]

// 'pong'
// token: u64
// [unspecified]

// 'scrt' - server cert
// cert bytes as der

// 'ccrt' - client cert
// cert bytes as der

// 'ckey' - client key
// key bytes as der

// 'xt??' (anything starting with 'xt')
// [unspecified]

use anyhow::{bail, Result};
use std::fmt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::wire;

pub type FourCc = [u8; 4];

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct HeaderHeader {
    pub four_cc: FourCc,
    pub data_len: u16,
}

impl HeaderHeader {
    pub async fn from(mut reader: impl AsyncReadExt + Unpin) -> Result<Self> {
        let mut buf = [0u8; 4 + 2];
        reader.read_exact(&mut buf).await?;
        Ok(HeaderHeader {
            four_cc: [buf[0], buf[1], buf[2], buf[3]],
            data_len: u16::from_le_bytes([buf[4], buf[5]]),
        })
    }

    pub async fn write_all(&self, mut writer: impl AsyncWriteExt + Unpin) -> Result<()> {
        let data_len = self.data_len.to_le_bytes();
        writer
            .write_all(&[
                self.four_cc[0],
                self.four_cc[1],
                self.four_cc[2],
                self.four_cc[3],
                data_len[0],
                data_len[1],
            ])
            .await?;
        Ok(())
    }

    pub fn empty(four_cc: FourCc) -> Self {
        HeaderHeader {
            four_cc,
            data_len: 0,
        }
    }

    pub fn finished() -> Self {
        HeaderHeader {
            four_cc: *b"fini",
            data_len: 0,
        }
    }

    pub fn ping() -> Self {
        HeaderHeader {
            four_cc: *b"ping",
            data_len: 8,
        }
    }
    pub fn pong() -> Self {
        HeaderHeader {
            four_cc: *b"pong",
            data_len: 8,
        }
    }

    pub fn error(string_length: u8) -> Self {
        HeaderHeader {
            four_cc: *b"errm",
            data_len: 4 + 1 + u16::from(string_length),
        }
    }

    pub fn data(len: usize) -> Self {
        HeaderHeader {
            four_cc: *b"data",
            data_len: u16::try_from(len).expect("long data len unsupported"),
        }
    }
}

#[tokio::test]
async fn test_header_header() {
    use std::io;

    let mut buf = Vec::new();
    let start = HeaderHeader {
        four_cc: *b"abcd",
        data_len: 259,
    };
    start.write_all(&mut buf).await.expect("infalliable / test");
    let end = HeaderHeader::from(io::Cursor::new(buf.as_slice()))
        .await
        .expect("test");

    assert_eq!(start, end);
}

impl fmt::Debug for HeaderHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Header({:?}, {})",
            String::from_utf8_lossy(&self.four_cc),
            self.data_len
        )
    }
}

pub async fn copy_framing(
    mut from_plain: impl AsyncReadExt + Unpin,
    mut to_framed: impl AsyncWriteExt + Unpin,
) -> Result<()> {
    // small buffer here; we need the whole frame to arrive at the other end before processing it,
    // and a smaller packet is more likely to arrive. We aren't flushing (maybe we should be flushing),
    // so the overhead of the small packet is very low; especially as (I assume) both read() and
    // write() here are heavily buffered. Intentionally, but potentially naively, ignoring the
    // underlying framing here; we've told it we're a stream transport, and we're building on top
    // of that stream, regardless of how it is implemented.
    let mut buf = [0u8; 256];

    loop {
        let found = from_plain.read(&mut buf).await?;
        let buf = &buf[..found];
        if buf.is_empty() {
            break;
        }

        wire::write_data(&mut to_framed, buf).await?;
    }

    Ok(())
}

pub async fn copy_unframing(
    mut from_framed: impl AsyncReadExt + Unpin,
    mut to_plain: impl AsyncWriteExt + Unpin,
) -> Result<()> {
    // arbitrary limit on the server; didn't fancy having a 65kB buffer here per connection,
    // seems excessive. Could have an auto-resizing Buf?
    let mut buf = [0u8; 8096];

    loop {
        let hh = HeaderHeader::from(&mut from_framed).await?;
        match &hh.four_cc {
            b"data" => (),
            b"fini" => break,
            _ => bail!("unsupported frame on established connection: {:?}", hh),
        };

        if usize::from(hh.data_len) > buf.len() {
            bail!("overlong data packet: {}", hh.data_len)
        }

        let buf = &mut buf[..usize::from(hh.data_len)];

        from_framed.read_exact(buf).await?;
        to_plain.write_all(buf).await?;
    }

    Ok(())
}
