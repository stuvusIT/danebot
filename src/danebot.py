#!/usr/bin/env python3

import argparse
import dns.message
import dns.query
import dns.rdtypes.ANY.TLSA
import dns.tsigkeyring
import dns.update
import os
import socket
import ssl
import subprocess
import sys
import textwrap
import time
import urllib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="danebot",
        description="Automated renewal of TLSA records for renewed certificates.",
    )
    parser.add_argument(
        "--cert-file",
        required=True,
        help=(
            "PEM-encoded file containing the new certificate and corresponding private"
            " key (unencrypted)."
        ),
    )
    parser.add_argument(
        "-d",
        "--domain",
        action="append",
        required=True,
        help=(
            "Domain to set TLSA record for. Must be one of the hostnames covered by the"
            " certificate. Can be specified multiple times."
        ),
    )
    parser.add_argument(
        "--hook",
        required=True,
        help=(
            "Program to run after the new TLSA record has propagated. The hook is run"
            " with the DANEBOT_CERT and DANEBOT_KEY environment variables containing"
            " the new certificate and key (unencrypted) in PEM-encoded format. The hook"
            " should typically install the new certificate on the server, e.g., by"
            " copying the certificate and key to the server's configuration and"
            " restarting the server."
        ),
    )
    parser.add_argument(
        "--probe",
        action="store_true",
        help=(
            "If this flag is given, perform probes whether the server uses the new"
            " certificate. For that, DaneBot connects to the first domain given via"
            " -d/--domain using the first TCP port given via --tcp."
        ),
    )
    parser.add_argument(
        "--propagation-time",
        type=int,
        default=60,
        help=(
            "Maximum time for DNS updates to propagate to secondary DNS servers. This"
            " increases the time DaneBot waits before running the hook."
        ),
    )
    parser.add_argument(
        "--rfc2136-nameserver",
        required=True,
        help=(
            "Authoritative nameserver used to query and update TLSA records. Must be an"
            " IP address, optionally followed by port. The default port is 53. Syntax"
            " examples: 1.2.3.4, 1.2.3.4:53, [2001:db8::1], [2001:db8::1]:53"
        ),
    )
    parser.add_argument(
        "--rfc2136-tsig-key",
        default=os.environ.get("DANEBOT_RFC2136_TSIG_KEY"),
        help=(
            "Name of the TSIG secret to sign DNS updates with. Defaults to the"
            " environment variable DANEBOT_RFC2136_TSIG_KEY."
        ),
    )
    parser.add_argument(
        "--rfc2136-tsig-secret",
        default=os.environ.get("DANEBOT_RFC2136_TSIG_SECRET"),
        help=(
            "TSIG secret to sign DNS update with. Defaults to the environment variable"
            " DANEBOT_RFC2136_TSIG_SECRET."
        ),
    )
    parser.add_argument(
        "--tcp",
        type=int,
        action="append",
        required=True,
        help=(
            "TCP ports to set TLSA records for. For instance, --tcp=25 corresponds to"
            ' the prefix "_25._tcp.". Can be specified multiple times.'
        ),
    )
    parser.add_argument("--ttl", type=int, default=3600, help="TTL for TLSA records.")
    args = parser.parse_args()

    try:
        DaneBot(args).run()
    except DaneBotError as e:
        print(f"Error: {e}")
        return 1

    return 0


class DaneBotError(Exception):
    pass


class DaneBot:
    def __init__(self, args):
        self.tcp_ports = args.tcp
        self.domains = args.domain
        self.ttl = args.ttl
        self.support_probes = args.probe
        self.propagation_time = args.propagation_time
        self.hook = args.hook

        try:
            url = urllib.parse.urlsplit("//" + args.rfc2136_nameserver)
            if url.port is not None:
                int(url.port)
        except Exception as e:
            raise DaneBotError(f"parsing --rfc2136-nameserver: {e}")
        try:
            self.rfc2136_ip = socket.getaddrinfo(
                url.hostname, None, 0, 0, socket.SOL_TCP
            )[0][4][0]
        except socket.gaierror as e:
            raise DaneBotError(f"resolving --rfc2136-nameserver: {e}")
        self.rfc2136_port = 53 if url.port is None else url.port

        if args.rfc2136_tsig_key is None:
            raise DaneBotError(
                "neither --rfc2136-tsig-key nor environment variable"
                " DANEBOT_RFC2136_TSIG_KEY is given"
            )
        if args.rfc2136_tsig_secret is None:
            raise DaneBotError(
                "neither --rfc2136-tsig-secret nor environment variable"
                " DANEBOT_RFC2136_TSIG_SECRET is given"
            )
        self.rfc2136_keyring = dns.tsigkeyring.from_text(
            {args.rfc2136_tsig_key: args.rfc2136_tsig_secret}
        )

        with open(args.cert_file, "rb") as cert_file:
            cert_pem = cert_file.read()
        self.cert = x509.load_pem_x509_certificate(cert_pem)
        self.key = serialization.load_pem_private_key(cert_pem, password=None)
        # TODO: Check if key belongs to cert
        self.cert_sha256 = self.cert.fingerprint(hashes.SHA256())
        self.dane_ee_hash = get_dane_ee_hash(self.cert)
        self.rdata = get_tlsa_rdata(self.dane_ee_hash)

        print(f"Loaded certificate {args.cert_file}:")
        print(f"  TLSA rdata = {self.rdata}")
        print(f"  Fingerprint = sha256:{self.cert_sha256.hex()}")

        # Determine server identity (i.e., list of domain names) as specified by
        # https://www.rfc-editor.org/rfc/rfc2818#page-5
        try:
            names = self.cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.DNSName)
        except x509.extensions.ExtensionNotFound:
            cn_attributes = self.cert.subject.get_attributes_for_oid(
                x509.oid.NameOID.COMMON_NAME
            )
            if not cn_attributes:
                raise DaneBotError(f"certificate has no dNSName nor Common Name")
            names = [cn_attributes[0].value]

        print(f"  Identity = {', '.join(names)}")

        for domain in self.domains:
            if domain not in names:
                raise DaneBotError(f"domain {domain} not covered by certificate")

    def run(self):
        if not self.support_probes or self.cert_sha256 != self.probe():
            previous_ttl = self.update(True)

            sleep_time = self.propagation_time + previous_ttl
            print(f"Waiting for {sleep_time} seconds ...")
            time.sleep(sleep_time)

            self.run_hook()

            if self.support_probes and self.cert_sha256 != self.probe():
                raise DaneBotError("server still doesn't use the new certificate")

        else:
            print("Skipping hook because the server already uses the new certificate.")

        self.update(False)

    def probe(self):
        assert self.support_probes
        hostname = self.domains[0]
        port = self.tcp_ports[0]
        try:
            live_cert = get_server_cert(hostname, port)
        except Exception as e:
            raise DaneBotError(f"probing {hostname}:{port}: {e}")
        sha256 = live_cert.fingerprint(hashes.SHA256())
        print(f"Probe: {hostname}:{port} has fingerprint sha256:{sha256.hex()}")
        if sha256 == self.cert_sha256:
            print("  matching the new certificate.")
        else:
            print("  distinct from the new certificate.")
        return sha256

    def update(self, keep_old_records):
        max_ttl = 0

        updates = {}

        for domain in self.domains:
            for tcp_port in self.tcp_ports:
                name = dns.name.from_text(f"_{tcp_port}._tcp.{domain}")
                rrset = dns.rrset.RRset(name, dns.rdataclass.IN, dns.rdatatype.TLSA)
                rrset.ttl = self.ttl
                rrset.add(self.rdata)

                request = dns.message.make_query(name, dns.rdatatype.TLSA)
                response = dns_query(request, self.rfc2136_ip, port=self.rfc2136_port)
                if len(response.answer) != 0:
                    print("Found records:")
                    print(textwrap.indent(str(response.answer[0]), "  "))
                    previous_ttl = response.answer[0].ttl
                    max_ttl = max(max_ttl, previous_ttl)
                    if keep_old_records:
                        if rrset.issubset(response.answer[0]):
                            print(f"No changes required for {name}")
                            continue
                        rrset.ttl = previous_ttl
                    elif rrset == response.answer[0] and rrset.ttl == previous_ttl:
                        print(f"No changes required for {name}")
                        continue

                if keep_old_records:
                    print(f"Will ADD the following records:")
                else:
                    print(f"Will REPLACE by the following records:")
                print(textwrap.indent(str(rrset), "  "))

                zone = self.resolve_zone(name)
                if zone not in updates:
                    updates[zone] = dns.update.Update(
                        zone, keyring=self.rfc2136_keyring
                    )
                if keep_old_records:
                    updates[zone].add(name, rrset)
                else:
                    updates[zone].replace(name, rrset)

        for zone, update in updates.items():
            response = dns_query(
                update,
                self.rfc2136_ip,
                port=self.rfc2136_port,
                allowable_rcodes=[dns.rcode.NOERROR],
            )
            print(f"Updated zone {zone}")

        return max_ttl

    def resolve_zone(self, fqdn):
        request = dns.message.make_query(fqdn, dns.rdatatype.SOA)
        response = dns_query(request, self.rfc2136_ip, port=self.rfc2136_port)
        if len(response.answer) != 0:
            # There's a SOA record, so the zone starts at fqdn.
            return fqdn
        if len(response.authority) != 0:
            # There's no SOA record, but the response contains an authority section
            # where we can extract the zone name.
            return response.authority[0].name
        raise DaneBotError(f"could not resolve zone name for {fqdn}")

    def run_hook(self):
        # The hook should typically copy the new certificate to the server's
        # configuration and restart the server.
        print("Running hook ...")
        env = os.environ.copy()
        env["DANEBOT_CERT"] = self.cert.public_bytes(serialization.Encoding.PEM)
        env["DANEBOT_KEY"] = self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        proc = subprocess.run([self.hook], env=env)
        if proc.returncode != 0:
            raise DaneBotError(f"hook failed with code {proc.returncode}")
        print("Hook returned successfully.")


def get_dane_ee_hash(cert):
    pk = cert.public_key()
    pk_pem = pk.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(pk_pem)
    return digest.finalize()


def get_tlsa_rdata(dane_ee_hash):
    return dns.rdtypes.ANY.TLSA.TLSA(
        dns.rdataclass.IN, dns.rdatatype.TLSA, 3, 1, 1, dane_ee_hash
    )


def get_server_cert(hostname, port):
    context = ssl._create_unverified_context()
    with socket.create_connection((hostname, port)) as sock:
        sock.recv(1000)
        sock.send(b"EHLO mail.example.com\nSTARTTLS\n")
        sock.recv(1000)
        with context.wrap_socket(sock, server_hostname=hostname) as sslsock:
            return x509.load_der_x509_certificate(sslsock.getpeercert(True))


def dns_query(
    request, ip, port, allowable_rcodes=[dns.rcode.NOERROR, dns.rcode.NXDOMAIN]
):
    try:
        response = dns.query.tcp(request, ip, port=port)
    except Exception as e:
        raise DaneBotError(f"failed DNS request @ {ip}: {e}")
    rcode = response.rcode()
    if rcode not in allowable_rcodes:
        raise DaneBotError(
            f"DNS request @ {ip} returned with rcode {dns.rcode.to_text(rcode)}"
        )
    return response


if __name__ == "__main__":
    sys.exit(main())
