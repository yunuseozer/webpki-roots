 # -*- coding: utf-8 -*-
import subprocess
import sys
import urllib

HEADER = """//!
//! This library is automatically generated from the Mozilla certificate
//! store via mkcert.org.  Don't edit it.
//!
//! The generation is done deterministically so you can verify it
//! yourself by inspecting and re-running the generation process.
//!

extern crate webpki;
extern crate time;

// See:
// https://blog.mozilla.org/security/2016/10/24/distrusting-new-wosign-and-startcom-certificates/
// https://wiki.mozilla.org/CA:WoSign_Issues
static OCTOBER_21_2016: i64 = 1477008000;

fn wosign_startcom_policy(_der: &[u8], _subj: &[u8], _spki: &[u8],
                          not_before: time::Timespec,
                          _not_after: time::Timespec) -> Result<(), webpki::Error> {
  if not_before.sec > OCTOBER_21_2016 {
    Err(webpki::Error::RejectedByPolicy)
  } else {
    Ok(())
  }
}
"""

CERT = """
  %(comment)s
  %(code)s,"""

excluded_cas = [
    # https://blog.mozilla.org/security/2015/04/02/distrusting-new-cnnic-certificates/
    # https://security.googleblog.com/2015/03/maintaining-digital-certificate-security.html
    "China Internet Network Information Center",
    "CNNIC",

    # See https://cabforum.org/pipermail/public/2016-September/008475.html.
    # Both the ASCII and non-ASCII names are required.
    "TÜRKTRUST",
    "TURKTRUST",
]

restricted_cas = {
    'StartCom': 'wosign_startcom_policy',
    'WoSign': 'wosign_startcom_policy',
}

def fetch_bundle():
    proc = subprocess.Popen(['curl',
                             'https://mkcert.org/generate/all/except/' +
                                "+".join([urllib.quote(x) for x in excluded_cas])],
            stdout = subprocess.PIPE)
    stdout, _ = proc.communicate()
    return stdout

def split_bundle(bundle):
    cert = ''
    for line in bundle.splitlines():
        if line.strip() != '':
            cert += line + '\n'
        if '-----END CERTIFICATE-----' in line:
            yield cert
            cert = ''

def calc_spki_hash(cert):
    """
    Use openssl to sha256 hash the public key in the certificate.
    """
    proc = subprocess.Popen(
            ['openssl', 'x509', '-noout', '-sha256', '-fingerprint'],
            stdin = subprocess.PIPE,
            stdout = subprocess.PIPE)
    stdout, _ = proc.communicate(cert)
    assert proc.returncode == 0
    assert stdout.startswith('SHA256 Fingerprint=')
    hash = stdout.replace('SHA256 Fingerprint=', '').replace(':', '')
    hash = hash.strip()
    assert len(hash) == 64
    return hash.lower()

def extract_header_spki_hash(cert):
    """
    Extract the sha256 hash of the public key in the header, for
    cross-checking.
    """
    line = [ll for ll in cert.splitlines() if ll.startswith('# SHA256 Fingerprint: ')][0]
    return line.replace('# SHA256 Fingerprint: ', '').replace(':', '').lower()

def unwrap_pem(cert):
    start = '-----BEGIN CERTIFICATE-----\n'
    end = '-----END CERTIFICATE-----\n'
    base64 = cert[cert.index(start)+len(start):cert.rindex(end)]
    return base64.decode('base64')

def extract(msg, name):
    lines = msg.splitlines()
    value = [ll for ll in lines if ll.startswith(name + ': ')][0]
    return value[len(name) + 2:].strip()

def convert_cert(cert_der):
    proc = subprocess.Popen(
            ['target/debug/process_cert'],
            stdin = subprocess.PIPE,
            stdout = subprocess.PIPE)
    stdout, _ = proc.communicate(cert_der)
    assert proc.returncode == 0
    return dict(
            subject = extract(stdout, 'Subject'),
            spki = extract(stdout, 'SPKI'),
            name_constraints = extract(stdout, 'Name-Constraints'),
            not_after = extract(stdout, 'Not-After'))

def commentify(cert):
    lines = cert.splitlines()
    lines = [ll[2:] if ll.startswith('# ') else ll for ll in lines]
    return '/*\n   * ' + ('\n   * '.join(lines)) + '\n   */'

def convert_bytes(hex):
    bb = hex.decode('hex')
    return bb.encode('string_escape').replace('"', '\\"')

def resolve_policy(subject_hex):
    subject = subject_hex.decode('hex')
    for subject_substr, policy_fn in restricted_cas.items():
        if subject_substr in subject:
            return 'Some(%s)' % policy_fn
    return 'None'

def print_root(cert, data):
    subject = convert_bytes(data['subject'])
    spki = convert_bytes(data['spki'])
    nc = data['name_constraints']
    nc = ('Some(b"%s")' % convert_bytes(nc)) if nc != 'None' else nc
    not_after = long(data['not_after'])
    policy = resolve_policy(data['subject'])

    print """  %s
  webpki::TrustAnchor {
    subject: b"%s",
    spki: b"%s",
    name_constraints: %s,
    not_after: %d,
    policy: %s
  },
""" % (commentify(cert), subject, spki, nc, not_after, policy)

if __name__ == '__main__':
    if sys.platform == "win32":
        import os, msvcrt
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)

    bundle = fetch_bundle()
    open('fetched.pem', 'w').write(bundle)

    certs = {}

    for cert in split_bundle(bundle):
        our_hash = calc_spki_hash(cert)
        their_hash = extract_header_spki_hash(cert)
        assert our_hash == their_hash

        cert_der = unwrap_pem(cert)
        data = convert_cert(cert_der)

        assert our_hash not in certs, 'duplicate cert'
        certs[our_hash] = (cert, data)

    print HEADER
    
    print """pub static ROOTS: [webpki::TrustAnchor<'static>; %d] = [""" % len(certs)

    # emit in sorted hash order for deterministic builds
    for hash in sorted(certs):
        cert, data = certs[hash]
        print_root(cert, data)

    print '];'
