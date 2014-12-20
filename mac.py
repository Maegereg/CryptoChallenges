import hash

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