import base64

import pgpdb
from pgpdump.utils import crc24

PGP_ARMOR_BASE = '''-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: django-pgpdb {0}

{1}
={2}
-----END PGP PUBLIC KEY BLOCK-----'''.format(pgpdb.__version__, '{0}', '{1}')

def encode_ascii_armor(data, crc=None):
    if crc is None:
        crc = crc24(bytearray(data))
        crc = ''.join([chr((crc >> i) & 0xff) for i in [16, 8, 0]])
        crc = base64.b64encode(crc)
    data = base64.b64encode(data)
    data = '\n'.join(data[i:i+64] for i in range(0, len(data), 64))
    return PGP_ARMOR_BASE.format(data, crc)

