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
// port: u16
// hostname_len: u8
// hostname: [u8; hostname_len]
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

// 'xt??' (anything starting with 'xt')
// [unspecified]

use anyhow::Result;
use futures_util::{AsyncReadExt, AsyncWriteExt};
use std::fmt;
use std::fmt::Formatter;

pub type FourCc = [u8; 4];

#[derive(Copy, Clone)]
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

    pub fn error(msg: &'static str) -> Self {
        HeaderHeader {
            four_cc: *b"errm",
            data_len: 4 + 1 + u16::try_from(msg.len()).expect("static messages are fixed length"),
        }
    }
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
