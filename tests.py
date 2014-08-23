from django.test import TestCase

import models

GPG_ALICE_KEY = """
Old: Public Key Packet(tag 6)(269 bytes)
	Ver 4 - new
	Public key creation time - Sun Jun 22 21:50:48 JST 2014
	Pub alg - RSA Encrypt or Sign(pub 1)
	RSA n(2048 bits) - ...
	RSA e(17 bits) - ...
Old: User ID Packet(tag 13)(36 bytes)
	User ID - alice (test key) <alice@example.com>
Old: Signature Packet(tag 2)(312 bytes)
	Ver 4 - new
	Sig type - Positive certification of a User ID and Public Key packet(0x13).
	Pub alg - RSA Encrypt or Sign(pub 1)
	Hash alg - SHA1(hash 2)
	Hashed Sub: signature creation time(sub 2)(4 bytes)
		Time - Sun Jun 22 21:50:48 JST 2014
	Hashed Sub: key flags(sub 27)(1 bytes)
		Flag - This key may be used to certify other keys
		Flag - This key may be used to sign data
	Hashed Sub: preferred symmetric algorithms(sub 11)(5 bytes)
		Sym alg - AES with 256-bit key(sym 9)
		Sym alg - AES with 192-bit key(sym 8)
		Sym alg - AES with 128-bit key(sym 7)
		Sym alg - CAST5(sym 3)
		Sym alg - Triple-DES(sym 2)
	Hashed Sub: preferred hash algorithms(sub 21)(5 bytes)
		Hash alg - SHA256(hash 8)
		Hash alg - SHA1(hash 2)
		Hash alg - SHA384(hash 9)
		Hash alg - SHA512(hash 10)
		Hash alg - SHA224(hash 11)
	Hashed Sub: preferred compression algorithms(sub 22)(3 bytes)
		Comp alg - ZLIB <RFC1950>(comp 2)
		Comp alg - BZip2(comp 3)
		Comp alg - ZIP <RFC1951>(comp 1)
	Hashed Sub: features(sub 30)(1 bytes)
		Flag - Modification detection (packets 18 and 19)
	Hashed Sub: key server preferences(sub 23)(1 bytes)
		Flag - No-modify
	Sub: issuer key ID(sub 16)(8 bytes)
		Key ID - 0xD5D7DA71C354960E
	Hash left 2 bytes - 04 5e 
	RSA m^d mod n(2047 bits) - ...
		-> PKCS-1
Old: Public Subkey Packet(tag 14)(269 bytes)
	Ver 4 - new
	Public key creation time - Sun Jun 22 21:50:48 JST 2014
	Pub alg - RSA Encrypt or Sign(pub 1)
	RSA n(2048 bits) - ...
	RSA e(17 bits) - ...
Old: Signature Packet(tag 2)(287 bytes)
	Ver 4 - new
	Sig type - Subkey Binding Signature(0x18).
	Pub alg - RSA Encrypt or Sign(pub 1)
	Hash alg - SHA1(hash 2)
	Hashed Sub: signature creation time(sub 2)(4 bytes)
		Time - Sun Jun 22 21:50:48 JST 2014
	Hashed Sub: key flags(sub 27)(1 bytes)
		Flag - This key may be used to encrypt communications
		Flag - This key may be used to encrypt storage
	Sub: issuer key ID(sub 16)(8 bytes)
		Key ID - 0xD5D7DA71C354960E
	Hash left 2 bytes - 9a eb 
	RSA m^d mod n(2047 bits) - ...
		-> PKCS-1

-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1

mQENBFOm0SgBCAC8BH6U1HHzzL1SXWpvjhf3sfAFJ8ciw5E854f70AkOOvi+fllB
D2OzmDqVB7dhBFwRUQ5i9ajPvNwYCXakwiVze44G2FMfOMbqqZaVTVUhpnYyMfB8
K0NgXQUqvfOdbGaKyUvIn1QwUtBQUwxwxIpJqXCGfAAXj5B23Q4VHSVGMnZ7KSbp
uqIsbQwhPx9F3nSZE5bX6NEFCM9nkTlBCrMRsSed08DTf6zKVNUjzRSj30iOuPWS
xaGbz+3mfIFwgVxYit850YgZfaQEkqrFsYPDA/bvI7C15I/3Oy2AavsPtPFroydp
JJ06fKDvC5s9V4Utyal5ttVvPcFw4o3LLlNtABEBAAG0JGFsaWNlICh0ZXN0IGtl
eSkgPGFsaWNlQGV4YW1wbGUuY29tPokBOAQTAQIAIgUCU6bRKAIbAwYLCQgHAwIG
FQgCCQoLBBYCAwECHgECF4AACgkQ1dfaccNUlg4EXgf/aIoYolj4Zs9Q8ck43BWx
EpjaC/vWgCQfUlRa9QI3IoWM37V52iLmba423/moF/eXGS6VtwdLq0k4GsuDfxIW
1Ojjwt4vtVR6UVtSNoI7y0s7yhpoRV+phMTcIbGlryMIrqWAwK4so/XbNDvqpVlS
RwLQnkDRkjMU7w8VZGrOyRucbZy6nZuH+nhialIq4VIPCu02HfAPgZGp7LH7EnMu
n25eHEvs45fk3Pus1BkYiCwt+nW5i1RYfwzWEZW9zkG2kDKadGxuN7fi75sGIGvy
gP+T7AuJGSl5BJKplxrKqefhQVhcpBgA3UYrb4I1wPHgtpGlBU2o+QKV9ZSeIvte
XLkBDQRTptEoAQgA2YqsTj9JniJkrr1x6g59io1GkP9z0JElzRl4kvG7WUkrhSPc
XkoLngcCur9lpxET2Wp7ou43zcKuiwsDxnsWwSvWfmg15N4BzYS6ulP7PSIpQlLb
srqFTR/iX0c7asgUE5Jpe8YEnThl2aAPkJlx47GQN1jhGxOkZhz3kIC+rG2d25ET
36eI0vw4oHO40nF9DihyHzfcD3tuuaOJ+AUPrDh7o97a8yIQmVU031GImC1DHQ9t
k9qkixCuejN1cfi7zqWclnd4nu3C/PJXLz0qzprhK0gXqgjZVBpCPQ5g/WV/Myw/
5H7vJC5WcV0lQilxtjgaHmpSu65XTaAHf4OlNQARAQABiQEfBBgBAgAJBQJTptEo
AhsMAAoJENXX2nHDVJYOmusH/0VDpB6353RsZzCj+eoV9mpew8gPo7jdwMGFVW3r
7ZfwCCE+9hMqQAPU4ewTtpy9SrzynZCG02vycaBhLJwcP1dKtvae1y8B8zh7zo9F
eLTUewHuyFRpyM5/fj1Dou89AOvDRaiJPaO3RQOmjGG9+D5hDS03CHBXOg/P0gYv
lc1myZNfRtU5+ezMEWA+tqyjyjj3W6nyobtpVtwgpA/od47/UcdGqSkzkmr+zqqH
amPMgSaahcvqPw2VFt4fi00ShN9EguwiV2vJes6VvDq1qE5Ap/zWBn/B7xIc70jD
hHtoB2/2gM/blPn5EPrIht6Kh9njBFYVk+OrV96NpJl08lM=
=xJuO
-----END PGP PUBLIC KEY BLOCK-----
"""

GPG_BOB_KEY = """
Old: Public Key Packet(tag 6)(269 bytes)
	Ver 4 - new
	Public key creation time - Sun Jun 22 21:55:43 JST 2014
	Pub alg - RSA Encrypt or Sign(pub 1)
	RSA n(2048 bits) - ...
	RSA e(17 bits) - ...
Old: User ID Packet(tag 13)(32 bytes)
	User ID - bob (test key) <bob@example.com>
Old: Signature Packet(tag 2)(312 bytes)
	Ver 4 - new
	Sig type - Positive certification of a User ID and Public Key packet(0x13).
	Pub alg - RSA Encrypt or Sign(pub 1)
	Hash alg - SHA1(hash 2)
	Hashed Sub: signature creation time(sub 2)(4 bytes)
		Time - Sun Jun 22 21:55:43 JST 2014
	Hashed Sub: key flags(sub 27)(1 bytes)
		Flag - This key may be used to certify other keys
		Flag - This key may be used to sign data
	Hashed Sub: preferred symmetric algorithms(sub 11)(5 bytes)
		Sym alg - AES with 256-bit key(sym 9)
		Sym alg - AES with 192-bit key(sym 8)
		Sym alg - AES with 128-bit key(sym 7)
		Sym alg - CAST5(sym 3)
		Sym alg - Triple-DES(sym 2)
	Hashed Sub: preferred hash algorithms(sub 21)(5 bytes)
		Hash alg - SHA256(hash 8)
		Hash alg - SHA1(hash 2)
		Hash alg - SHA384(hash 9)
		Hash alg - SHA512(hash 10)
		Hash alg - SHA224(hash 11)
	Hashed Sub: preferred compression algorithms(sub 22)(3 bytes)
		Comp alg - ZLIB <RFC1950>(comp 2)
		Comp alg - BZip2(comp 3)
		Comp alg - ZIP <RFC1951>(comp 1)
	Hashed Sub: features(sub 30)(1 bytes)
		Flag - Modification detection (packets 18 and 19)
	Hashed Sub: key server preferences(sub 23)(1 bytes)
		Flag - No-modify
	Sub: issuer key ID(sub 16)(8 bytes)
		Key ID - 0x3C8F7607CA580F9E
	Hash left 2 bytes - 5e 70 
	RSA m^d mod n(2048 bits) - ...
		-> PKCS-1
Old: Public Subkey Packet(tag 14)(269 bytes)
	Ver 4 - new
	Public key creation time - Sun Jun 22 21:55:43 JST 2014
	Pub alg - RSA Encrypt or Sign(pub 1)
	RSA n(2048 bits) - ...
	RSA e(17 bits) - ...
Old: Signature Packet(tag 2)(287 bytes)
	Ver 4 - new
	Sig type - Subkey Binding Signature(0x18).
	Pub alg - RSA Encrypt or Sign(pub 1)
	Hash alg - SHA1(hash 2)
	Hashed Sub: signature creation time(sub 2)(4 bytes)
		Time - Sun Jun 22 21:55:43 JST 2014
	Hashed Sub: key flags(sub 27)(1 bytes)
		Flag - This key may be used to encrypt communications
		Flag - This key may be used to encrypt storage
	Sub: issuer key ID(sub 16)(8 bytes)
		Key ID - 0x3C8F7607CA580F9E
	Hash left 2 bytes - a8 60 
	RSA m^d mod n(2046 bits) - ...
		-> PKCS-1

-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1

mQENBFOm0k8BCAC1r3JzpCyUjSIMyDm35lOJItSe5hLK7aIHxscs5oxmQiLpR80d
6pisPWiwA9gMDs700LpE+m/QtR4y17MlNU2S1i1RLlt118SEnwD+g/fTBZrCOmuy
FWLizoRhtlLcu3ir4j47APfu1I3De5x3t1TeBuSY41rSkxXlZ8G9hlu2xAO6MmCE
fJpNc/tHt9cTXTMGKapVJK/F9dQZ+T2NgPf0nyr5EIfpx+GckZlx3qFT+SleN/UY
ETk2LL6ElpwARVmcyDv3J9BuLekA0aQSR9GqmDpQmMFBoXds69pBhWtXu228puop
8LSwO7ZF6c/flTp8xniRlpIEejk4WchhSYdlABEBAAG0IGJvYiAodGVzdCBrZXkp
IDxib2JAZXhhbXBsZS5jb20+iQE4BBMBAgAiBQJTptJPAhsDBgsJCAcDAgYVCAIJ
CgsEFgIDAQIeAQIXgAAKCRA8j3YHylgPnl5wCACvW5ihaa9Ovmh8hnpBzOdD9A0V
kTdXwHU0E2G4O0+jLxnbpP8s9apw8aYuOS7IlNBA0qoaCDQUU1XEs/TyZJNwVZww
FqwBSiAlxPR0ZBAVLGmuRPC/pA1LgFKEf95A3VKlqcOuFmBnA+o4FqUTHQ+hsXDs
icNflufWU/p0kAhP+8gAkrYdO2RTYqO9+qRFULb/U5/NX2iIIo+w7v8k3dVzDKD6
SQJ8IksFJ7iJb90zPu14xlWOHYZl9SPvD/hM+XwRdDRwnF2W1O1QT0+RZlbhZdB5
6opzVyonaVwSZ6X4wtIy9nhBVjHv9xaQKh7bYCtk9RAauDZ10R72KANdeoaQuQEN
BFOm0k8BCAC0xTBFoQ467Q0ye2tNQ1rUJ7xn6sQ03kiTUr7U+NLvJzKF2B6odGNA
Y+wBFAvkYDZ+AgzhfyWos3x+VuYulctPXR8KMUdbE4euoP+wu/jmXr5PocmxNQgg
92iHQ5hzxJXnBoDPAMSYl3Cux19+/jGoc44LgJP9Xm7gBwo7keq0+NhGlbCgGKKl
DxBr/Jqb87pa9Y+WBXN1LL1h8sLabAN6kEMx1GiAq3G8L9HEEAnOkXgn4vnQp+7s
KrSqxKEbqw28vB9FjPcC3ISzM5R/fGb1hanD/YAA5VEbZriUL9OnLN2AxNzfWQPI
1G3K1LcDGcrBo9FG8G0plulm93dorvvlABEBAAGJAR8EGAECAAkFAlOm0k8CGwwA
CgkQPI92B8pYD56oYAf+POvglwkna4396mqIAhhq7nozSbF26fX8fT3r7r2Hge+m
OgJZjLLVTKVtuUx1bb1SPaKdd+TW5A8xM1Nnjg1xB6WPaa3XXKkkd8Ty4kvrUqUk
yevXl0R/cBscnO04WeUic5ErHUaAo9NZH2smPaOcwW7zvIiYm8R6orb/zeXJqltn
2sVHuFNYjgcC8OxcreS5SQu/l6kfybRCKmdC7UaPfNNbesH+IuTwuLv5rQh125l2
Mpga1NHRG7vfaqDSp41mOel/Y1MbFgcFcs3Q274Olr9hxHeMIJAYow+RAOhgYXjQ
GeykHHGfctbPAwE/06+sspYamO7XjhmPcbdXd+fX9w==
=AXuc
-----END PGP PUBLIC KEY BLOCK-----
"""

class PGPKeyModelTest(TestCase):
    def setUp(self):
        self.ALICE = models.PGPKeyModel.objects.save_to_storage(None, GPG_ALICE_KEY)

    def tearDown(self):
        self.ALICE.delete()

    def test_save_to_storage(self):
        self.BOB = models.PGPKeyModel.objects.save_to_storage(None, GPG_BOB_KEY)

        self.assertNotEqual(self.ALICE.uid, self.BOB.uid)
        self.assertNotEqual(self.ALICE.file, self.BOB.file)
        self.assertEqual(self.ALICE.user, None)
        self.assertEqual(self.BOB.user, None)
        self.assertEqual(self.ALICE.crc24, 'xJuO')
        self.assertEqual(self.BOB.crc24, 'AXuc')
        self.assertEqual(self.ALICE.is_compromised, False)
        self.assertEqual(self.BOB.is_compromised, False)

        self.BOB.delete()

    def test_userid(self):
        self.assertEqual(self.ALICE.userids.count(), 1)
        userid = self.ALICE.userids.all()[0]
        self.assertEqual(userid.userid, 'alice (test key) <alice@example.com>')

    def test_publickey(self):
        self.assertEqual(self.ALICE.public_keys.count(), 2)
        keys = self.ALICE.public_keys.all()
        sign = keys[0]
        enc = keys[1]
        self.assertEqual(sign.is_sub, False)
        creation_time = sign.creation_time.strftime('%Y-%m-%dT%H:%M:%S')
        self.assertEqual(creation_time, '2014-06-22T12:50:48')
        self.assertEqual(sign.expiration_time, None)
        self.assertEqual(sign.algorithm, 1)  # RSA_ENC_SIGN
        self.assertEqual(sign.fingerprint, '4b3292e956b577ad703443f4d5d7da71c354960e')
        self.assertEqual(sign.keyid, 'd5d7da71c354960e')

        self.assertEqual(enc.is_sub, True)
        creation_time = enc.creation_time.strftime('%Y-%m-%dT%H:%M:%S')
        self.assertEqual(creation_time, '2014-06-22T12:50:48')
        self.assertEqual(enc.expiration_time, None)
        self.assertEqual(enc.algorithm, 1)  # RSA_ENC_SIGN
        self.assertEqual(enc.fingerprint, '089d58a247da0553a46ff04c9f0ff40fd27061e1')
        self.assertEqual(enc.keyid, '9f0ff40fd27061e1')

