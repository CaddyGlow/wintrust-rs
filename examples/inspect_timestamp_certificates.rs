//! Read-only extraction of authenticated timestamp certificate diagnostics.
use anyhow::{Context, Result};
use der::Decode;
use sha2::{Digest, Sha256};
use wintrust::portable::{signed, timestamp};
use x509_cert::Certificate;

fn main() -> Result<()> {
    let path = std::env::args().nth(1).context("CATALOG_PATH")?;
    let bytes = std::fs::read(path)?;
    let catalog = signed::verify_signed_data(
        &bytes,
        &signed::SignedDataOptions::new("1.3.6.1.4.1.311.10.1".parse()?),
    )?;
    let mut output = Vec::new();
    for signer in catalog.signers {
        for (oid, values) in signer.unsigned_attributes {
            if oid != timestamp::RFC3161_ATTRIBUTE && oid != timestamp::MICROSOFT_RFC3161_ATTRIBUTE
            {
                continue;
            }
            for token in values {
                let cms = signed::verify_signed_data(
                    &token,
                    &signed::SignedDataOptions::new("1.2.840.113549.1.9.16.1.4".parse()?),
                )?;
                for bytes in cms.certificates {
                    let certificate = Certificate::from_der(&bytes)?;
                    let extensions: Vec<_> = certificate.tbs_certificate.extensions.iter().flatten().map(|e| serde_json::json!({"oid":e.extn_id.to_string(),"critical":e.critical,"der_hex":hex::encode(e.extn_value.as_bytes())})).collect();
                    output.push(serde_json::json!({"subject":certificate.tbs_certificate.subject.to_string(),"issuer":certificate.tbs_certificate.issuer.to_string(),"sha256":hex::encode(Sha256::digest(&bytes)),"extensions":extensions}));
                }
            }
        }
    }
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}
