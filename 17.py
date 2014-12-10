import aes
import padding
import ecboracle
import xor

import random
import string

plaintexts = ["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]

persistentKey = ""

#Returns a tuple of an  a ciphertext encrypted under a persistent key and the associated IV
def cbcEncrypter():
	global persistentKey
	if persistentKey == "":
		persistentKey = ecboracle.generateRandomKey()
	IV = ecboracle.generateRandomIV()
	ciphertext = aes.aesCBCEncrypt(random.sample(plaintexts, 1)[0], persistentKey, IV)
	print aes.aesCBCDecrypt(ciphertext, persistentKey, IV)
	return (ciphertext, IV)

#Returns true if the ciphertext is correctly padded, false otherwise
def paddingOracle(ciphertext, IV):
	global persistentKey
	plaintext = ""
	try:
		plaintext = aes.aesCBCDecrypt(ciphertext, persistentKey, IV)
	except padding.PaddingError:
		return False
	return True

#Performs a padding oracle attack
def decryptCBC(ciphertext, IV, blocklen=16):
	blockList = [IV] + [ciphertext[i*blocklen:(i+1)*blocklen] for i in range(len(ciphertext)/blocklen)]
	plaintext = ""
	for blockNum in range(1, len(blockList))[::-1]:
		#The plaintext values of the current block, starting from the highest order byte
		plaintextBlock = ""
		for charNum in range(blocklen)[::-1]:
			#Both the number of padding bytes, and their value
			paddingValue = blocklen-charNum		
			#The value we must xor the known plaintext values with in order to get the correct padding
			plaintextXors = xor.xorByteStrings(chr(paddingValue)*len(plaintextBlock), plaintextBlock)
			for xorValue in range(1, 256)+[0]:
				xorBlock = string.rjust(chr(xorValue)+plaintextXors, blocklen, chr(0))
				modifiedBlocks = blockList[:blockNum+1]
				modifiedBlocks[-2] = xor.xorByteStrings(modifiedBlocks[-2], xorBlock)
				if paddingOracle( "".join(modifiedBlocks[1:blockNum]) + modifiedBlocks[-1] , modifiedBlocks[0] ):
					plaintextBlock = chr(xorValue^paddingValue)+plaintextBlock
					break
		plaintext = plaintextBlock+plaintext
	return plaintext

if __name__ == "__main__":
	ciphertext = cbcEncrypter()
	print ciphertext
	print paddingOracle(ciphertext[0], ciphertext[1])
	print paddingOracle(ciphertext[0][:16], ciphertext[1])
	print repr(decryptCBC(ciphertext[0], ciphertext[1]))