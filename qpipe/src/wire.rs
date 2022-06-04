use anyhow::{bail, ensure, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::frame::HeaderHeader;

pub async fn write_data(mut writer: impl AsyncWriteExt + Unpin, buf: &[u8]) -> Result<()> {
    HeaderHeader::data(buf.len()).write_all(&mut writer).await?;
    writer.write_all(buf).await?;

    Ok(())
}

pub async fn write_error(
    mut writer: impl AsyncWriteExt + Unpin,
    code: u32,
    msg: &'static str,
) -> Result<()> {
    let string_length = u8::try_from(msg.len()).expect("static messages are fixed length");

    HeaderHeader::error(string_length)
        .write_all(&mut writer)
        .await?;
    writer.write_all(&code.to_le_bytes()).await?;
    writer.write_all(&[string_length]).await?;
    writer.write_all(msg.as_bytes()).await?;

    Ok(())
}

#[derive(Debug, Clone)]
pub struct Establish {
    // `t`cp, `u`dp,
    pub protocol: u8,
    // max length: 255
    pub address_port: String,
}

pub async fn write_establish(
    mut writer: impl AsyncWriteExt + Unpin,
    establish: &Establish,
) -> Result<()> {
    let addr_len = u8::try_from(establish.address_port.len())
        .context("address lengths must be under 255 bytes")?;
    let data_len = 1 + 1 + u16::from(addr_len);

    HeaderHeader {
        four_cc: *b"con1",
        data_len,
    }
    .write_all(&mut writer)
    .await?;

    // tcp/udp
    writer.write_all(&[establish.protocol]).await?;
    writer.write_all(&[addr_len]).await?;
    writer.write_all(establish.address_port.as_bytes()).await?;

    Ok(())
}

pub fn parse_establish(buf: &[u8]) -> Result<Establish> {
    ensure!(buf.len() >= 2, "impossibly short request");
    let protocol = buf[0];
    let name_length = usize::from(buf[1]);
    let buf = &buf[2..];
    ensure!(buf.len() >= name_length, "name doesn't fit in request");
    let address_port = String::from_utf8(buf[..name_length].to_vec())?;
    Ok(Establish {
        protocol,
        address_port,
    })
}

pub async fn read_okay(mut reader: impl AsyncReadExt + Unpin) -> Result<()> {
    let resp = HeaderHeader::from(&mut reader).await?;
    match &resp.four_cc {
        b"okay" => (),
        _ => bail!("unexpected response {:?}", resp),
    }
    // TODO: consume body
    Ok(())
}
