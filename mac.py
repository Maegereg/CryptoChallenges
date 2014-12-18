import hash

def keyPrefixMac(message, key, hashFunction):
	return hashFunction(key+message)

def sha1KeyPrefix(message, key):
	return keyPrefixMac(message, key, hash.sha1)