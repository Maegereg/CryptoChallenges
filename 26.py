import aes
import ecboracle
import kvparser
import random
import xor

persistentKey = ""
persistentNonce = ""

def oracle(plaintext):
	global persistentKey
	global persistentNonce
	if persistentKey == "":
		persistentKey = ecboracle.generateRandomKey()
		persistentNonce = random.randint(0, 2**64-1)

	plaintext = plaintext.replace(";", "").replace("=", "")
	fullPlaintext = "comment1=cooking%20MCs;userdata="+plaintext+";comment2=%20like%20a%20pound%20of%20bacon"
	return aes.aesCTREncrypt(fullPlaintext, persistentKey, persistentNonce)

def validateAdmin(ciphertext):
	global persistentKey
	global persistentNonce
	plaintext = aes.aesCTRDecrypt(ciphertext, persistentKey, persistentNonce)
	return ";admin=true;" in plaintext

#returns a ciphertext that will validate based only on the encryption oracle
def breakValidation(oracle):
	stringToInsert = ";admin=true;"
	bytesToInsert = 'a'*len(stringToInsert)
	insertionPoint = findCTRInsertionPoint(oracle)
	ciphertextToModify = oracle(bytesToInsert)
	xorValue = xor.xorByteStrings(stringToInsert, bytesToInsert)
	modifiedCiphertext = xor.xorByteStrings((chr(0)*insertionPoint)+xorValue+(chr(0)*(len(oracle(""))-insertionPoint)), ciphertextToModify)
	return modifiedCiphertext


#returns the position into which plaintext provided to the oracle is inserted
def findCTRInsertionPoint(oracle):
	defaultText = oracle("")
	comparisonText = oracle(chr(0))
	for i in range(len(defaultText)):
		if defaultText[i] != comparisonText[i]:
			return i


if __name__ == "__main__":
	test = oracle(";admin=true;")
	print validateAdmin(test)
	print validateAdmin(breakValidation(oracle))