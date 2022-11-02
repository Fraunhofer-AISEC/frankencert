from __future__ import annotations

import argparse
import collections
import functools
import io
import os
import random
import string
import sys
import typing
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.backends.openssl.backend import Backend

# This is so much pain… :(
from cryptography.hazmat.backends.openssl.encode_asn1 import (
    _encode_asn1_int_gc,
    _encode_name_gc,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    PRIVATE_KEY_TYPES,
    PUBLIC_KEY_TYPES,
)
from cryptography.x509.extensions import Extension, ExtensionType
from cryptography.x509.name import Name
from cryptography.x509.oid import NameOID

log = functools.partial(print, file=sys.stderr, flush=True)
FRANKENCERT_T = tuple[PRIVATE_KEY_TYPES, list[x509.Certificate]]


def _convert_to_naive_utc_time(time: datetime.datetime) -> datetime:
    """Normalizes a datetime to a naive datetime in UTC.

    time -- datetime to normalize. Assumed to be in UTC if not timezone
            aware.
    """
    if time.tzinfo is not None:
        offset = time.utcoffset()
        offset = offset if offset else timedelta()
        return time.replace(tzinfo=None) - offset
    else:
        return time


class Version(Enum):
    v1 = 0
    v3 = 2


class FrankenBackend(Backend):
    def create_x509_certificate(
        self,
        builder: x509.CertificateBuilder,
        private_key: PRIVATE_KEY_TYPES,
        algorithm: typing.Optional[hashes.HashAlgorithm],
    ) -> x509.Certificate:
        if builder._public_key is None:
            raise TypeError("Builder has no public key.")
        self._x509_check_signature_params(private_key, algorithm)

        # Resolve the signature algorithm.
        evp_md = self._evp_md_x509_null_if_eddsa(private_key, algorithm)

        # Create an empty certificate.
        x509_cert = self._lib.X509_new()
        x509_cert = self._ffi.gc(x509_cert, self._lib.X509_free)

        # Set the x509 version.
        res = self._lib.X509_set_version(x509_cert, builder._version.value)
        self.openssl_assert(res == 1)

        # Set the subject's name.
        res = self._lib.X509_set_subject_name(
            x509_cert, _encode_name_gc(self, builder._subject_name)
        )
        self.openssl_assert(res == 1)

        # Set the subject's public key.
        res = self._lib.X509_set_pubkey(
            x509_cert,
            builder._public_key._evp_pkey,  # type: ignore[union-attr]
        )
        self.openssl_assert(res == 1)

        # Set the certificate serial number.
        serial_number = _encode_asn1_int_gc(self, builder._serial_number)
        res = self._lib.X509_set_serialNumber(x509_cert, serial_number)
        self.openssl_assert(res == 1)

        # Set the "not before" time.
        self._set_asn1_time(
            self._lib.X509_getm_notBefore(x509_cert), builder._not_valid_before
        )

        # Set the "not after" time.
        self._set_asn1_time(
            self._lib.X509_getm_notAfter(x509_cert), builder._not_valid_after
        )

        # Add extensions.
        self._create_x509_extensions(
            extensions=builder._extensions,
            handlers=self._extension_encode_handlers,
            x509_obj=x509_cert,
            add_func=self._lib.X509_add_ext,
            gc=True,
        )

        # Set the issuer name.
        res = self._lib.X509_set_issuer_name(
            x509_cert, _encode_name_gc(self, builder._issuer_name)
        )
        self.openssl_assert(res == 1)

        # Sign the certificate with the issuer's private key.
        res = self._lib.X509_sign(
            x509_cert,
            private_key._evp_pkey,  # type: ignore[union-attr]
            evp_md,
        )
        if res == 0:
            errors = self._consume_errors_with_text()
            raise ValueError("Signing failed", errors)

        return self._ossl2cert(x509_cert)


_backend = FrankenBackend()


def _get_backend(backend: typing.Optional[Backend]) -> Backend:
    global _backend
    return _backend


class CertificateBuilder:
    def __init__(
        self,
        issuer_name=None,
        subject_name=None,
        public_key=None,
        serial_number=None,
        not_valid_before=None,
        not_valid_after=None,
        extensions=[],
    ) -> None:
        self._version = Version.v3
        self._issuer_name = issuer_name
        self._subject_name = subject_name
        self._public_key = public_key
        self._serial_number = serial_number
        self._not_valid_before = not_valid_before
        self._not_valid_after = not_valid_after
        self._extensions = extensions

    def issuer_name(self, name: Name) -> CertificateBuilder:
        """
        Sets the CA's distinguished name.
        """
        return CertificateBuilder(
            name,
            self._subject_name,
            self._public_key,
            self._serial_number,
            self._not_valid_before,
            self._not_valid_after,
            self._extensions,
        )

    def subject_name(self, name: Name) -> CertificateBuilder:
        """
        Sets the requestor's distinguished name.
        """
        return CertificateBuilder(
            self._issuer_name,
            name,
            self._public_key,
            self._serial_number,
            self._not_valid_before,
            self._not_valid_after,
            self._extensions,
        )

    def public_key(
        self,
        key: PUBLIC_KEY_TYPES,
    ) -> CertificateBuilder:
        """
        Sets the requestor's public key (as found in the signing request).
        """
        return CertificateBuilder(
            self._issuer_name,
            self._subject_name,
            key,
            self._serial_number,
            self._not_valid_before,
            self._not_valid_after,
            self._extensions,
        )

    def serial_number(self, number: int) -> CertificateBuilder:
        """
        Sets the certificate serial number.
        """
        return CertificateBuilder(
            self._issuer_name,
            self._subject_name,
            self._public_key,
            number,
            self._not_valid_before,
            self._not_valid_after,
            self._extensions,
        )

    def not_valid_before(self, time: datetime.datetime) -> CertificateBuilder:
        """
        Sets the certificate activation time.
        """
        time = _convert_to_naive_utc_time(time)
        return CertificateBuilder(
            self._issuer_name,
            self._subject_name,
            self._public_key,
            self._serial_number,
            time,
            self._not_valid_after,
            self._extensions,
        )

    def not_valid_after(self, time: datetime.datetime) -> CertificateBuilder:
        """
        Sets the certificate expiration time.
        """
        time = _convert_to_naive_utc_time(time)
        return CertificateBuilder(
            self._issuer_name,
            self._subject_name,
            self._public_key,
            self._serial_number,
            self._not_valid_before,
            time,
            self._extensions,
        )

    def add_extension(
        self, extval: ExtensionType, critical: bool
    ) -> CertificateBuilder:
        """
        Adds an X.509 extension to the certificate.
        """
        extension = Extension(extval.oid, critical, extval)
        return CertificateBuilder(
            self._issuer_name,
            self._subject_name,
            self._public_key,
            self._serial_number,
            self._not_valid_before,
            self._not_valid_after,
            self._extensions + [extension],
        )

    def sign(
        self,
        private_key: PRIVATE_KEY_TYPES,
        algorithm: hashes.HashAlgorithm,
        backend=None,
    ) -> x509.Certificate:
        """
        Signs the certificate using the CA's private key.
        """
        backend = _get_backend(backend)
        return backend.create_x509_certificate(self, private_key, algorithm)


def random_serial_number() -> int:
    return int.from_bytes(os.urandom(20), "big") >> 1


class FrankenCertGenerator:
    ec_ciphers = {
        "ed25519": ed25519.Ed25519PrivateKey,
        "ed448": ed448.Ed448PrivateKey,
        "secp256r1": ec.SECP256R1,
        "secp384r1": ec.SECP384R1,
        "secp521r1": ec.SECP521R1,
    }
    hash_algos = {
        'md5': hashes.MD5,
        "sha1": hashes.SHA1,
        "sha224": hashes.SHA224,
        "sha256": hashes.SHA256,
        "sha384": hashes.SHA384,
        "sha512": hashes.SHA512,
        "sha512_224": hashes.SHA512_224,
        "sha512_256": hashes.SHA512_256,
        "blake2b": functools.partial(hashes.BLAKE2b, 64),
        "blake2s": functools.partial(hashes.BLAKE2s, 32),
        "sha3-224": hashes.SHA3_224,
        "sha3-256": hashes.SHA3_256,
        "sha3-384": hashes.SHA3_384,
        "sha3-512": hashes.SHA3_512,
    }

    def __init__(
        self,
        seed: list[x509.Certificate],
        ca_cert: x509.Certificate,
        ca_priv: PRIVATE_KEY_TYPES,
        config: dict,
    ) -> None:
        self.seed = seed
        self.ca_cert = ca_cert
        self.ca_priv = ca_priv
        self.digest = config["digest"]
        self.ext_mod_probability: float = config["ext_mod_probability"]
        self.flip_probability: float = config["flip_probability"]
        self.invalid: bool = config["invalid"]
        self.invalid_ts_probability: float = config["invalid_ts_probability"]
        self.keylen: int = config["keylen"]
        self.keytype: str = config["keytype"]
        self.max_depth: int = config["max_depth"]
        self.max_extensions: int = config["max_extensions"]
        self.randomize_hash: bool = config["randomize_hash"]
        self.randomize_serial: bool = config["randomize_serial"]
        self.randomize_keytype: bool = config["randomize_keytype"]
        self.self_signed_prob: float = config["self_signed_prob"]

    def _generate_priv(self) -> PRIVATE_KEY_TYPES:
        key: Optional[PRIVATE_KEY_TYPES] = None
        t = self.keytype
        # TODO: Consider RSA in the randomized cert stuff as well.
        if t == "rsa":
            size = self.keylen
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=size,
            )
        else:
            if self.randomize_keytype:
                cipher = random.choice(list(self.ec_ciphers.values()))
            else:
                cipher = self.ec_ciphers[t]
            if isinstance(cipher, ed25519.Ed25519PrivateKey):
                key = cipher.generate()
            else:
                key = ec.generate_private_key(cipher)
        assert key
        return key

    def _generate_cert(
        self,
        issuer: Optional[x509.Name],
        signing_key: PRIVATE_KEY_TYPES,
        extensions: dict,
    ) -> tuple[PRIVATE_KEY_TYPES, x509.Certificate]:
        private_key = self._generate_priv()
        public_key = private_key.public_key()
        builder = CertificateBuilder()

        # Set random not_before and not_after values.
        not_before = None
        not_after = None
        if random.random() < self.invalid_ts_probability:
            if random.random() < 0.5:
                # Generate not yet valid cert.
                not_before = datetime.now() + timedelta(days=1)
            else:
                # Generate expired cert.
                not_after = datetime.now() - timedelta(days=1)
        else:
            pick = random.choice(self.seed)
            not_before = pick.not_valid_before
            pick = random.choice(self.seed)
            not_after = pick.not_valid_after

        assert not_before is not None
        assert not_after is not None

        builder = builder.not_valid_before(not_before)
        builder = builder.not_valid_after(not_after)

        # Set serial number.
        if self.randomize_serial:
            builder = builder.serial_number(x509.random_serial_number())
        else:
            pick = random.choice(self.seed)
            s = pick.serial_number
            s = s if s > 0 else s * -1
            builder = builder.serial_number(s)

        # Set subject.
        pick = random.choice(self.seed)
        builder = builder.subject_name(pick.subject)

        # Set issuer.
        if issuer is None:
            pick = random.choice(self.seed)
            builder = builder.issuer_name(pick.issuer)
        elif self.invalid:
            builder = builder.issuer_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, _random_str()),
                    ]
                )
            )
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(_random_str())]),
                critical=False,
            )
        else:
            builder = builder.issuer_name(issuer)
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(issuer.rfc4514_string())]),
                critical=False,
            )

        builder = builder.public_key(public_key)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )

        # Do stuff with extensions.
        sample = random.randint(0, self.max_extensions)
        choices = random.sample(extensions.keys(), sample)
        new_extensions = [random.choice(extensions[name]) for name in choices]
        for extension in new_extensions:
            # FIXME: How to implement this with python cryptography?
            # if random.random() < self.config["ext_mod_probability"]:
            #     randstr = "".join(chr(random.randint(0, 255)) for i in range(7))
            #     extension.set_data(randstr)

            try:
                if random.random() < self.flip_probability:
                    builder.add_extension(
                        extension.value, critical=not extension.critical
                    )
                else:
                    builder.add_extension(extension.value, critical=extension.critical)
            # Skip duplicates…
            except ValueError:
                pass

        cert = None
        # ED25519 expects None here.
        if self.randomize_hash:
            digest = random.choice(list(self.hash_algos.values()))()
        else:
            digest = self.hash_algos[self.digest]()
        # ED25519 MUST NOT be used with a hash function, since
        # hashing is backed into the signing digest itself!
        if issuer:
            if isinstance(signing_key, ed25519.Ed25519PrivateKey):
                digest = None
            # Generate cert chain.
            cert = builder.sign(
                private_key=signing_key,
                algorithm=digest,
            )
        else:
            if isinstance(private_key, ed25519.Ed25519PrivateKey):
                digest = None
            # Generate self signed cert.
            cert = builder.sign(
                private_key=private_key,
                algorithm=digest,
            )
        assert cert is not None
        return private_key, cert

    def generate(
        self,
        number: int,
        extensions: Optional[dict] = None,
    ) -> list[FRANKENCERT_T]:
        log("Generating frankencerts…")

        if extensions is None:
            extensions = get_extension_dict(self.seed)
        self.max_extensions = min(self.max_extensions, len(extensions.keys()))

        # generate the key pairs once and reuse them for faster
        # frankencert generation
        privs = []
        for _ in range(self.max_depth):
            priv = self._generate_priv()
            privs.append(priv)

        assert len(privs) == self.max_depth

        certs = []
        for i in range(number):
            log(f"\rProgress: {i+1}/{number}", end="")

            chain = []
            signing_key = self.ca_priv
            issuer = self.ca_cert.issuer
            priv = None
            length = random.randint(1, self.max_depth)

            if length == 1 and random.random() < self.self_signed_prob:
                issuer = None

            for j in range(length):
                priv, cert = self._generate_cert(
                    issuer,
                    signing_key,
                    extensions,
                )
                signing_key = priv
                issuer = cert.issuer
                chain.append(cert)
            certs.append((priv, list(reversed(chain))))

        log()
        assert len(certs) == number
        return certs


def _random_str() -> str:
    r = ""
    s = list(string.printable)
    for _ in range(random.randint(1, 128)):
        r += random.choice(s)
    return r


def _dump_certs_file(path: Path, franken_certs: list[FRANKENCERT_T]) -> None:
    for i, franken_cert in enumerate(franken_certs):
        key, cert_list = franken_cert
        p = path.joinpath(f"frankencert-{i}.pem")
        buf = io.BytesIO()
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        buf.write(pem)
        for cert in cert_list:
            pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
            buf.write(pem)
        p.write_bytes(buf.getbuffer())


def _dump_certs_stdout(franken_certs: list[FRANKENCERT_T]) -> None:
    for franken_cert in franken_certs:
        key, cert_list = franken_cert
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        print(pem.decode())
        for cert in cert_list:
            pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
            print(pem.decode())


def dump_certs(path: Path, certs: list[FRANKENCERT_T]) -> None:
    log(f"Writing frankencerts to {path}…")

    if str(path) == "-":
        _dump_certs_stdout(certs)
    else:
        base = Path(path)
        if not base.exists():
            base.mkdir(parents=True)
        _dump_certs_file(base, certs)


def load_seed(path: Path) -> list[x509.Certificate]:
    log("Loading seed certificates…")

    certs = []
    certsfiles = list(path.iterdir())

    with open("pyLoad-fails.txt", "w") as f:
        for i, infile in enumerate(certsfiles):
            log(f"\rProgress: {i+1}/{len(certsfiles)}", end="")
            data = infile.read_bytes()
            try:
                cert = x509.load_pem_x509_certificate(data)
                certs.append(cert)
            except Exception:
                f.write(f"failed: {infile}\n")
    return certs


def load_ca(path: Path) -> tuple[PRIVATE_KEY_TYPES, x509.Certificate]:
    buf = path.read_bytes()
    ca_cert = x509.load_pem_x509_certificate(buf)
    ca_priv = serialization.load_pem_private_key(buf, password=None)
    return ca_priv, ca_cert


def get_extension_dict(certs: list[x509.Certificate]) -> dict:
    d = collections.defaultdict(dict)
    for cert in certs:
        for extension in cert.extensions:
            d[extension.oid.dotted_string][extension.value] = extension
    for k in d.keys():
        d[k] = list(d[k].values())
    return d


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate specially crafted SSL certificates for "
            "testing certificate validation code in SSL/TLS "
            "implementations"
        )
    )
    parser.add_argument(
        "-s",
        "--seed",
        metavar="PATH",
        required=True,
        type=Path,
        help="Path to folder containing seed certificates",
    )
    parser.add_argument(
        "-c",
        "--ca",
        metavar="PATH",
        required=True,
        type=Path,
        help="Path to root ca file, containing priv key and certificate",
    )
    parser.add_argument(
        "-o",
        "--out",
        metavar="PATH",
        default="-",
        type=Path,
        help="Out directory, or stdout with '-'",
    )
    parser.add_argument(
        "--load-only",
        action="store_true",
        help="Only load seeds and do not generate frankencerts",
    )
    parser.add_argument(
        "-k",
        "--keytype",
        default="secp256r1",
        help="Specify the keytype, e.g. secp256r1, see openssl",
    )
    parser.add_argument(
        "-l",
        "--keylen",
        metavar="INT",
        type=int,
        default=2048,
        help="Keylength, only for RSA keys",
    )
    parser.add_argument(
        "-d",
        "--digest",
        default="sha256",
        help="Hash algorithm to generate the signature",
    )
    parser.add_argument(
        "-n",
        "--number",
        type=int,
        metavar="INT",
        default=10,
        help="Quartity of generated certs",
    )
    parser.add_argument(
        "-i",
        "--invalid",
        action="store_true",
        help="Introduce more brokenness",
    )
    parser.add_argument(
        "--max-extensions",
        type=int,
        metavar="INT",
        default=20,
        help="Max X.509 extensions, currently not used",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        metavar="INT",
        default=3,
        help="Maximum trust chain length",
    )
    parser.add_argument(
        "--ext-mod-prob",
        type=float,
        metavar="FLOAT",
        default=0.0,
    )
    parser.add_argument(
        "--flip-critical-prob",
        type=float,
        metavar="FLOAT",
        default=0.25,
    )
    parser.add_argument(
        "--self-signed-prob",
        type=float,
        metavar="FLOAT",
        default=0.25,
    )
    parser.add_argument(
        "--invalid-ts-prob",
        type=float,
        metavar="FLOAT",
        default=0.0,
    )
    parser.add_argument(
        "--randomize-serial",
        action="store_true",
        help="Randomize the serial number of the generated certificates",
    )
    parser.add_argument(
        "--randomize-hash",
        action="store_true",
        help="Randomize the hash function generating the signatures [!BUGS!]",
    )
    parser.add_argument(
        "--randomize-keytype",
        action="store_true",
        help="Use different keys: ec, ed25519, …",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    seed = load_seed(args.seed)
    if args.load_only:
        sys.exit(0)
    ca_priv, ca_cert = load_ca(args.ca)
    config = {
        "digest": args.digest,
        "ext_mod_probability": args.ext_mod_prob,
        "flip_probability": args.flip_critical_prob,
        "invalid": args.invalid,
        "invalid_ts_probability": args.invalid_ts_prob,
        "keylen": args.keylen,
        "keytype": args.keytype,
        "max_depth": args.max_depth,
        "max_extensions": args.max_extensions,
        "randomize_hash": args.randomize_hash,
        "randomize_serial": args.randomize_serial,
        "randomize_keytype": args.randomize_keytype,
        "self_signed_prob": args.self_signed_prob,
    }

    frankenstein = FrankenCertGenerator(seed, ca_cert, ca_priv, config)
    frankencerts = frankenstein.generate(args.number)
    dump_certs(args.out, frankencerts)
