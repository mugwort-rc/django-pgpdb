import base64
import calendar
import datetime
import urllib

import pgpdb
from pgpdump.packet import (
    PublicKeyPacket, PublicSubkeyPacket, SignaturePacket, UserIDPacket,
    UserAttributePacket
)
from pgpdump.utils import crc24

PGP_ARMOR_BASE = '''-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: django-pgpdb {0}

{1}
={2}
-----END PGP PUBLIC KEY BLOCK-----'''.format(pgpdb.__version__, '{0}', '{1}')

SAFE_7BIT = r' !"#$%&\'()*+,-./;<=>?@[\\]^_`{|}~'

def encode_ascii_armor(data, crc=None):
    if crc is None:
        crc = crc24(bytearray(data))
        crc = ''.join([chr((crc >> i) & 0xff) for i in [16, 8, 0]])
        crc = base64.b64encode(crc)
    data = base64.b64encode(str(data))
    data = '\n'.join(data[i:i+64] for i in range(0, len(data), 64))
    return PGP_ARMOR_BASE.format(data, crc)

def parse_public_key_packets(pgp):
    result = []
    tmp = []
    start = 0
    for packet in pgp.packets():
        if ( tmp and
             isinstance(packet, PublicKeyPacket) and
             not isinstance(packet, PublicSubkeyPacket) ):
            last = tmp[-1].data
            next = pgp.data.index(last) + len(last)
            data = str(pgp.data)[start:next]
            start = next
            result.append((data, tmp))
            tmp = []
        tmp.append(packet)
    if tmp:
        data = pgp.data[start:]
        result.append((data, tmp))
    return result

def is_valid_packets(packets):
    pubkey = 0  # (1 <= pubkey) / One Public-Key packet
    revsig = 0  # (0 <= revsig) / Zero or more revocation signatures
    userid = 0  # (1 <= userid) / One or more User ID packets
    pubsig = 0  # (0 <= pubsig) / After each User ID packet, zero or more Signature packets (certifications)
    usratt = 0  # (0 <= usratt) / Zero or more User Attribute packets
    attsig = 0  # (0 <= attsig) / After each User Attribute packet, zero or more Signature packets (certifications)
    subkey = 0  # (0 <= subkey) / Zero or more Subkey packets
    subsig = 0  # (0 <= subsig) / After each Subkey packet, one Signature packet,
    aftrev = 0  # plus optionally a revocation
    other  = 0
    length  = len(packets)
    for i in range(length):
        packet = packets[i]
        if i == 0 and isinstance(packet, PublicKeyPacket):
            pubkey = 1
        elif pubkey == 1:
            if ( userid == 0 and
                 isinstance(packet, SignaturePacket) and
                 packet.raw_sig_type == 0x30):
                revsig += 1
            elif ( userid >= 0 and
                   isinstance(packet, UserIDPacket)):
                userid += 1
            elif ( userid > 0 and usratt == 0 and
                   ( isinstance(packets[i-1], UserIDPacket) or
                     ( isinstance(packets[i-1], SignaturePacket) and
                       packets[i-1].raw_sig_type in [0x10, 0x11, 0x12, 0x13]
                     )
                   ) and
                   isinstance(packet, SignaturePacket) and
                   packet.raw_sig_type in [0x10, 0x11, 0x12, 0x13]):
                pubsig += 1
            elif ( userid > 0 and
                   isinstance(packet, UserAttributePacket)):
                usratt += 1
            elif ( usratt > 0 and
                   ( isinstance(packets[i-1], UserAttributePacket) or
                     ( isinstance(packets[i-1], SignaturePacket) and
                       packets[i-1].raw_sig_type in [0x10, 0x11, 0x12, 0x13]
                     )
                   ) and
                   isinstance(packet, SignaturePacket) and
                   packet.raw_sig_type in [0x10, 0x11, 0x12, 0x13]):
                attsig += 1
            elif isinstance(packet, PublicSubkeyPacket):
                subkey += 1
            elif ( subkey > 0 and
                   isinstance(packet, SignaturePacket) and
                   packet.raw_sig_type == 0x18):
                subsig += 1
            elif ( subkey > 0 and
                   isinstance(packet, SignaturePacket) and
                   packet.raw_sig_type in [0x20, 0x28, 0x30]):
                aftrev += 1
            else:
                other += 1
    return other == 0

def keys_ascii_armor(keys):
    if keys.count() == 1:
        return keys[0].ascii_armor()
    else:
        data = ''
        for key in keys:
            data += key.read()
        return encode_ascii_armor(data)

def build_machine_readable_indexes(keys):
    result = []
    result.append(['info', '1', str(keys.count())])
    for key in keys:
        # pub
        first = key.public_keys.first()
        keyid = first.keyid
        algo = str(first.algorithm)
        keylen = str(first.bits)
        creation_unix = int(calendar.timegm(first.creation_time.timetuple()))
        creationdate = str(creation_unix)
        expirationdate = ''
        if first.expiration_time:
            expiration_unix = int(calendar.timegm(first.expiration_time.timetuple()))
            expirationdate = str(expiration_unix)
        flags = ''
        if key.is_revoked:
            flags += 'r'
        if expirationdate and first.expiration_time < datetime.datetime.utcnow():
            flags += 'e'
        result.append([
            'pub',
            keyid,
            algo,
            keylen,
            creationdate,
            expirationdate,
            flags
        ])

        # uid
        for uid in key.userids.all():
            escaped_uid = urllib.quote(uid.userid, SAFE_7BIT)
            sig = uid.signatures.filter(keyid=keyid).first()
            creation_unix = int(calendar.timegm(sig.creation_time.timetuple()))
            creationdate = str(creation_unix)
            expirationdate = ''
            if sig.expiration_time:
                expiration_unix = int(calendar.timegm(sig.expiration_time.timetuple()))
                expirationdate = str(expiration_unix)
            flags = ''
            if expirationdate and first.expiration_time < datetime.datetime.utcnow():
                flags += 'e'
            result.append([
                'uid',
                escaped_uid,
                creationdate,
                expirationdate,
                flags
            ])
    return '\n'.join([':'.join(x) for x in result])

