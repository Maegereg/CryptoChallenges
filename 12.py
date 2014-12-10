from ecboracle import *

AESKey = ""

UNKNOWN_STRING = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

def encryptionBlackBox(plaintext):
	global AESKey
	if AESKey == "":
		AESKey = generateRandomKey()

	fullPlaintext = plaintext+convert.b64ToByteString(UNKNOWN_STRING)
	return aes.aesECBEncrypt(fullPlaintext, AESKey)

if __name__ == "__main__":
	if determineIfOracleECB(encryptionBlackBox):
		print breakECBOracle(encryptionBlackBox)