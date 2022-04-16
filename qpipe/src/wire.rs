use anyhow::Result;
use tokio::io::AsyncWriteExt;

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
