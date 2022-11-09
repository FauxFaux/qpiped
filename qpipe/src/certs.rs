use std::fs::Permissions;
use std::path::Path;
use std::{fs, io};

use anyhow::{anyhow, bail, ensure, Context, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequest, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose,
};

type KeyPair = (rustls::Certificate, rustls::PrivateKey);

pub fn server(state_dir: impl AsRef<Path>, names: &[&str]) -> Result<KeyPair> {
    let path = state_dir.as_ref();
    fs::create_dir_all(&path)
        .with_context(|| anyhow!("failed to create state directory {:?}", path))?;

    remove_access(path)?;

    let cert_path = path.join("cert.der");
    let key_path = path.join("key.der");

    let (cert, key) = match fs::read(&cert_path) {
        Ok(cert) => (cert, fs::read(key_path)?),
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
            generate_server_certs(&cert_path, &key_path, names)?
        }
        Err(e) => bail!("failed to read cert from {:?}: {:?}", cert_path, e),
    };

    let key = rustls::PrivateKey(key);
    let cert = rustls::Certificate(cert);
    Ok((cert, key))
}

pub fn parse_client(buf: &[u8]) -> Result<CertificateSigningRequest> {
    Ok(CertificateSigningRequest::from_der(buf)?)
}

pub fn mint_client(
    ca_key: &rustls::PrivateKey,
    client_csr: &CertificateSigningRequest,
) -> Result<rustls::Certificate> {
    // ensure!(client_csr.params.is_ca == IsCa::ExplicitNoCa, "{:?} should be ExplicitNoCa", client_csr.params.is_ca);
    let mut ca_builder = rcgen::CertificateParams::new([]);
    ca_builder.key_pair = Some(rcgen::KeyPair::from_der(&ca_key.0)?);
    let ca = rcgen::Certificate::from_params(ca_builder)?;
    let cert = client_csr.serialize_der_with_signer(&ca)?;
    Ok(rustls::Certificate(cert))
}

#[test]
fn test_gen_client() -> Result<()> {
    let state_dir = tempfile::tempdir()?;
    let (_ca_cert, ca_key) = server(state_dir, &["localhost"])?;
    let (csr, client_keys) = generate_client_certs()?;
    let client_cert = mint_client(&ca_key, &parse_client(&csr)?)?;
    Ok(())
}

// TODO: well this isn't the worst security nightmare of a return type ever
/// @return (csr, private_key_pair)
pub fn generate_client_certs() -> Result<(Vec<u8>, Vec<u8>)> {
    let mut params = CertificateParams::new(vec!["client".to_string()]);
    params.is_ca = IsCa::ExplicitNoCa;
    let client = Certificate::from_params(params)?;
    let req = client.serialize_request_der()?;
    Ok((req, client.get_key_pair().serialize_der()))
}

fn generate_server_certs(
    cert_path: &Path,
    key_path: &Path,
    names: &[&str],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut params =
        rcgen::CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "qpiped server");
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    use KeyUsagePurpose::*;
    params.key_usages = vec![KeyCertSign, CrlSign, DigitalSignature];
    use ExtendedKeyUsagePurpose::*;
    params.extended_key_usages = vec![ServerAuth];
    let cert = Certificate::from_params(params)?;
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
    Ok(())
}
