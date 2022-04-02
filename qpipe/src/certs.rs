use std::fs::Permissions;
use std::path::Path;
use std::{fs, io};

use anyhow::{anyhow, bail, Context, Result};

pub fn server(
    state_dir: impl AsRef<Path>,
    names: &[&str],
) -> Result<(rustls::Certificate, rustls::PrivateKey)> {
    let path = state_dir.as_ref();
    fs::create_dir_all(&path)
        .with_context(|| anyhow!("failed to create state directory {:?}", path))?;

    remove_access(&path)?;

    let cert_path = path.join("cert.der");
    let key_path = path.join("key.der");

    let (cert, key) = match fs::read(&cert_path) {
        Ok(cert) => (cert, fs::read(key_path)?),
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
            generate_certs(&cert_path, &key_path, names)?
        }
        Err(e) => bail!("failed to read cert from {:?}: {:?}", cert_path, e),
    };

    let key = rustls::PrivateKey(key);
    let cert = rustls::Certificate(cert);
    Ok((cert, key))
}

fn generate_certs(cert_path: &Path, key_path: &Path, names: &[&str]) -> Result<(Vec<u8>, Vec<u8>)> {
    let cert = rcgen::generate_simple_self_signed(
        names.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
    )?;
    let key = cert.serialize_private_key_der();
    let cert = cert.serialize_der()?;
    fs::write(&cert_path, &cert)
        .with_context(|| anyhow!("failed to write certificate to {:?}", cert_path))?;
    fs::write(&key_path, &key).context("failed to write private key")?;
    Ok((cert, key))
}

#[cfg(unix)]
fn remove_access(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    Ok(fs::set_permissions(path, Permissions::from_mode(0o700))?)
}

#[cfg(windows)]
fn remove_access(path: &Path) -> Result<()> {
    // windows is secure by default
}
