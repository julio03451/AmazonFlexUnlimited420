from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
import datetime
import os
import random
import json
import hashlib
import string

from pyasn1.type import univ, namedtype, tag, namedval
from pyasn1.codec.der.encoder import encode



class SecurityLevel(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('Software', 0),
        ('TrustedEnvironment', 1),
        ('StrongBox', 2)
    )

class VerifiedBootState(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('Verified', 0),
        ('SelfSigned', 1),
        ('Unverified', 2),
        ('Failed', 3)
    )

class RootOfTrust(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('verifiedBootKey', univ.OctetString()),
        namedtype.NamedType('deviceLocked', univ.Boolean()),
        namedtype.NamedType('verifiedBootState', VerifiedBootState()),
        namedtype.OptionalNamedType('verifiedBootHash', univ.OctetString())
    )

class AuthorizationList(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('purpose', univ.SetOf(componentType=univ.Integer()).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
        namedtype.OptionalNamedType('algorithm', univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
        namedtype.OptionalNamedType('keySize', univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
        namedtype.OptionalNamedType('digest', univ.SetOf(componentType=univ.Integer()).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5))),
        namedtype.OptionalNamedType('ecCurve', univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 10))),
        namedtype.OptionalNamedType('noAuthRequired', univ.Null().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 503))),
        namedtype.OptionalNamedType('creationDateTime', univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 701))),
        namedtype.OptionalNamedType('origin', univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 702))),
        namedtype.OptionalNamedType('rootOfTrust', RootOfTrust().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 704))),
        namedtype.OptionalNamedType('osVersion', univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 705))),
        namedtype.OptionalNamedType('osPatchLevel', univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 706))),
        namedtype.OptionalNamedType('attestationApplicationId', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 709))),
        namedtype.OptionalNamedType('attestationIdSerial', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 713))),
        namedtype.OptionalNamedType('vendorPatchLevel', univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 718))),
        namedtype.OptionalNamedType('bootPatchLevel', univ.Integer().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 719)))
    )

class KeyDescription(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('attestationVersion', univ.Integer()),
        namedtype.NamedType('attestationSecurityLevel', univ.Enumerated()),
        namedtype.NamedType('keymasterVersion', univ.Integer()),
        namedtype.NamedType('keymasterSecurityLevel', univ.Enumerated()),
        namedtype.NamedType('attestationChallenge', univ.OctetString()),
        namedtype.OptionalNamedType('uniqueId', univ.OctetString()),
        namedtype.NamedType('softwareEnforced', AuthorizationList()),
        namedtype.NamedType('teeEnforced', AuthorizationList())
    )

def create_custom_extension(nonce):
    random_key = os.urandom(32)
    random_hash = os.urandom(32)
    sha256_boot_key = hashlib.sha256(random_key).hexdigest()
    sha256_boot_hash = hashlib.sha256(random_hash).hexdigest()

    # Root Of Trust
    root_of_trust = RootOfTrust().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 704))
    root_of_trust['verifiedBootKey'] = bytes.fromhex(f'{sha256_boot_key}')
    root_of_trust['deviceLocked'] = True
    root_of_trust['verifiedBootState'] = 0
    root_of_trust['verifiedBootHash'] = bytes.fromhex(f'{sha256_boot_hash}')

    # Tee Enforced
    tee_enforced = AuthorizationList()
    tee_enforced['purpose'] = univ.SetOf(componentType=univ.Integer()).subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
    tee_enforced['purpose'].extend([2])
    tee_enforced['algorithm'] = 3
    tee_enforced['keySize'] = 256
    tee_enforced['digest'] = univ.SetOf(componentType=univ.Integer()).subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 5))
    tee_enforced['digest'].extend([4, 6])
    tee_enforced['ecCurve'] = 1
    tee_enforced['noAuthRequired'] = b''
    tee_enforced['origin'] = 0
    tee_enforced['rootOfTrust'] = root_of_trust
    tee_enforced['osVersion'] = 0
    tee_enforced['osPatchLevel'] = 202201
    tee_enforced['vendorPatchLevel'] = 20220102
    tee_enforced['bootPatchLevel'] = 202201

    # Software Enforced
    software_enforced = AuthorizationList()
    software_enforced['creationDateTime'] = int(datetime.datetime.utcnow().timestamp() * 1000)
    software_enforced['attestationApplicationId'] = bytes.fromhex('3041311b30190411636f6d2e616d617a6f6e2e72616262697402041241582f312204202f19adeb284eb36f7f07786152b9a1d14b21653203ad0b04ebbf9c73ab6d7625')

    key_description = KeyDescription()
    key_description['attestationVersion'] = 3
    key_description['attestationSecurityLevel'] = 1
    key_description['keymasterVersion'] = 200
    key_description['keymasterSecurityLevel'] = 1
    key_description['attestationChallenge'] = f'{nonce}'.encode()
    key_description['uniqueId'] = b''
    key_description['softwareEnforced'] = software_enforced
    key_description['teeEnforced'] = tee_enforced

    return encode(key_description)

def create_private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
        backend=default_backend()
    )
    return private_key

def create_custom_cert(ca_private_key, nonce):
    ec_private_key = ec.generate_private_key(
        ec.SECP256R1(), default_backend()
    )

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"Android Keystore Key"),]))
    builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"Android Keystore Key"),]))
    builder = builder.public_key(ec_private_key.public_key())
    builder = builder.serial_number(1)
    builder = builder.not_valid_before(datetime.datetime(1970, 1, 1))
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))

    attestation_extension = create_custom_extension(nonce)
    builder = builder.add_extension(x509.UnrecognizedExtension(oid=x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17"), value=attestation_extension), critical=False)

    certificate = builder.sign(
        private_key=ca_private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    # Convert certificate to PEM format and decode to string format
    converted_certificate = certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')\
        .replace("-----BEGIN CERTIFICATE-----", "")\
        .replace("-----END CERTIFICATE-----", "")\
        .replace("\n", "")

    return converted_certificate, ec_private_key

def create_complete_chain(custom_cert):
    # Load existing certs
    with open('chains.json', 'r') as f:
        data = json.load(f)

    # Get a list of chain keys (identifiers)
    chain_keys = list(data['chains'].keys())

    # Select a random chain key
    random_chain_key = random.choice(chain_keys)

    # Add a certificate to the beginning of the randomly selected chain
    data['chains'][random_chain_key].insert(0, custom_cert)

    complete_chain = data['chains'][random_chain_key]

    return complete_chain

class Chain:
    def get_chain(nonce):
        ca_private_key = create_private_key()

        custom_cert, ec_private_key = create_custom_cert(ca_private_key, nonce)

        complete_chain = create_complete_chain(custom_cert)

        return complete_chain, ec_private_key
