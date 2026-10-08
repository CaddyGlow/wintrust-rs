This fixture contains the genuine Windows 10 19041.1 NetFx Shared WCF TcpPortSharing package catalog and MUM preserved from the disposable native pending oracle. Original source routes are `Windows\servicing\Packages\Microsoft-Windows-NetFx-Shared-WCF-TcpPortSharing~31bf3856ad364e35~amd64~~10.0.19041.1.{cat,mum}`.

The nested RFC3161 SignedData certificate collection is not in DER SET order. RFC5652 sections 3 and 10.2.3 allow BER CMS CertificateSet representation; section 5.4 still requires canonical DER signed attributes. The implementation accepts only collection ordering here: certificate encodings, lengths, signed attributes, cryptographic signatures, member digest, timestamp imprint, ESS binding and certificate chains remain validated. Attribute-certificate choices are retained and never trusted as signing certificates or anchors.

The explicit fixture policy requires a verified timestamp and pins the seventh legacy Microsoft TSA leaf DER SHA-256 `a76393c1e699d1354eb556e2cb067f9743f06a3aa850e0fa844b78d359044845` in addition to the six prior observed leaves. Revocation is explicitly disabled, SHA-1 is prohibited, and the three Microsoft root inputs remain pinned. This is a source authentication regression, not a servicing or boot completion proof.

Primary specification: https://www.rfc-editor.org/rfc/rfc5652.html

Retained SHA-256 values:

```json
{
  "microsoft-root-2011.der": "847df6a78497943f27fc72eb93f9a637320a02b561d0a91b09e87a7807ed7c61",
  "member.mum": "9fbc7ab2099238faa333bb77a1f62a39b1b106cb9598ead24146781d1495af38",
  "microsoft-rsa-root-2017.der": "c741f70f4b2a8d88bf2e71c14122ef53ef10eba0cfa5e64cfa20f418853073e0",
  "catalog.cat": "65377930eb23d0b0f4fe56a61580a2dae0aaeca4abfad63b59a46d7b99018f42",
  "microsoft-root-2010.der": "df545bf919a2439c36983b54cdfc903dfa4f37d3996d8d84b4c31eec6f3c163e",
  "policy.json": "adaf408b75522b5f45880613f935ca6b743d936a5dfea77ce48990591f085fdc"
}
```
