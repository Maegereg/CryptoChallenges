import convert
import hash
import xor

def keyPrefixMac(message, key, hashFunction):
	return hashFunction(key+message)

def verifyKeyPrefix(message, key, mac, hashFunction):
	return mac == keyPrefixMac(message, key, hashFunction)

def sha1KeyPrefix(message, key):
	return keyPrefixMac(message, key, hash.sha1)

def verifySha1KeyPrefix(message, key, mac):
	return verifyKeyPrefix(message, key, mac, hash.sha1)

def md4KeyPrefix(message, key):
	return keyPrefixMac(message, key, hash.md4)

def verifyMd4KeyPrefix(message, key, mac):
	return verifyKeyPrefix(message, key, mac, hash.md4)


def hMAC(message, key, hashFunction, blockSize):
	if len(key) > blockSize:
		key = hashFunction(key)
	key = key.ljust(blockSize, chr(0))

	oKeyPad = xor.xorByteStrings(chr(0x5c)*blockSize, key)
	iKeyPad = xor.xorByteStrings(chr(0x36)*blockSize, key)

	return hashFunction(oKeyPad+ convert.intToByteString(hashFunction(iKeyPad+message)))

def hMAC_SHA1(message, key):
	return hMAC(message, key, hash.sha1, 64)

def HMAC_SHA256(message, key):
	return hMAC(message, key, hash.sha256, 64)