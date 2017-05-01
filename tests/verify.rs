extern crate webpki;
extern crate webpki_roots;
extern crate untrusted;
extern crate time;

use untrusted::Input;
use time::Timespec;

static ALL_ALGORITHMS: [&webpki::SignatureAlgorithm; 12] = [
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA1,
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    &webpki::RSA_PKCS1_3072_8192_SHA384,
    &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
];

#[test]
fn tubitak_name_constraint_works() {
    let root = include_bytes!("data/tubitak/root.der");
    let inter = include_bytes!("data/tubitak/inter.der");
    let subj = include_bytes!("data/tubitak/subj.der");
    let now = Timespec::new(1493668479, 0);

    let chain = [
        Input::from(inter),
        Input::from(root)
    ];
    let cert = webpki::EndEntityCert::from(Input::from(subj))
        .unwrap();
    cert.verify_is_valid_tls_server_cert(&ALL_ALGORITHMS,
                                         &webpki_roots::ROOTS,
                                         &chain,
                                         now)
        .unwrap();
    cert.verify_is_valid_for_dns_name(Input::from(b"testssl.kamusm.gov.tr"))
        .unwrap();
}
