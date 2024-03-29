use std::fs::Permissions;
use std::path::Path;
use std::{fs, io};

use anyhow::{anyhow, bail, ensure, Context, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequest, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose,
};
use rustls::PrivateKey;

type KeyPair = (rustls::Certificate, rustls::PrivateKey);
#[derive(Clone, Debug)]
pub struct Csr(Vec<u8>);

// note that, despite the return types, there's not a single iota
// of validation of the returned objects in this method
fn load_or_generate(
    root: impl AsRef<Path>,
    short_name: &str,
    generate: impl FnOnce() -> Result<KeyPair>,
) -> Result<KeyPair> {
    let path = root.as_ref();
    let cert_path = path.join(format!("{short_name}.cert"));
    let key_path = path.join(format!("{short_name}.key"));

    match fs::read(&cert_path) {
        Ok(cert) => Ok((
            rustls::Certificate(cert),
            rustls::PrivateKey(
                fs::read(key_path).context("loading key after already loading cert")?,
            ),
        )),
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
            let (cert, key) = generate()?;
            fs::write(&cert_path, &cert.0)
                .with_context(|| anyhow!("failed to write certificate to {:?}", cert_path))?;
            fs::write(&key_path, &key.0).context("failed to write private key")?;
            Ok((cert, key))
        }
        Err(e) => Err(e).with_context(|| anyhow!("failed to read cert from {cert_path:?}")),
    }
}

pub fn server(state_dir: impl AsRef<Path>, names: &[&str]) -> Result<KeyPair> {
    load_or_generate(state_dir, "server", || generate_server_certs(names))
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
    let client_cert = mint_client(&ca_key, &parse_client(&csr.0)?)?;
    Ok(())
}

pub fn generate_client_certs() -> Result<(Csr, rustls::PrivateKey)> {
    let params = CertificateParams::new(vec!["client".to_string()]);
    let client = Certificate::from_params(params)?;
    let req = client.serialize_request_der()?;
    Ok((
        Csr(req),
        rustls::PrivateKey(client.get_key_pair().serialize_der()),
    ))
}

fn generate_server_certs(names: &[&str]) -> Result<KeyPair> {
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
    Ok((rustls::Certificate(cert), PrivateKey(key)))
}

fn load_or_generate_key(state_dir: impl AsRef<Path>) -> Result<KeyPair> {
    let key = rcgen::KeyPair::generate(&CertificateParams::default().alg)?;
    unimplemented!()
}

// client generates a key in a file; it's their key everywhere
// connect to a server, load our key, turn it into a CSR, send it to the server
// server replies with our cert and their cert
// store this .. certificate pair under, say, the server's cert's fingerprint
// client picks this during negotiation, sigh
// much better to just not store it; in memory only? If so, why bother saving the key.

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
