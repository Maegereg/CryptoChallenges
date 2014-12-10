import aes
import ecboracle
import kvparser
import xor

persistentKey = ""
persistentIV = ""

def oracle(plaintext):
	global persistentKey
	global persistentIV
	if persistentKey == "":
		persistentKey = ecboracle.generateRandomKey()
		persistentIV = ecboracle.generateRandomIV()

	plaintext = plaintext.replace(";", "").replace("=", "")
	fullPlaintext = "comment1=cooking%20MCs;userdata="+plaintext+";comment2=%20like%20a%20pound%20of%20bacon"
	return aes.aesCBCEncrypt(fullPlaintext, persistentKey, persistentIV)

def validateAdmin(ciphertext):
	global persistentKey
	global persistentIV
	plaintext = aes.aesCBCDecrypt(ciphertext, persistentKey, persistentIV)
	return ";admin=true;" in plaintext

#returns a ciphertext that will validate based only on the encryption oracle
def breakValidation(oracle, validater, blocklen = 16):
	stringToInsert = ";admin=true;"
	bytesToInsert = 'a'*len(stringToInsert)
	blockNum = findCBCInsertionBlock(oracle, blocklen)
	#Add padding to the beginning until the choice section is pushed to the next block
	for i in range(1, 17):
		ciphertextToModify = oracle((chr(0)*i)+bytesToInsert)
		blockToModify = ciphertextToModify[(blockNum)*blocklen:(blockNum+1)*blocklen]
		modifiedBlock = xor.xorByteStrings(xor.xorByteStrings(stringToInsert, bytesToInsert).ljust(blocklen), blockToModify)
		modifiedText = ciphertextToModify[:(blockNum)*blocklen]+modifiedBlock+ciphertextToModify[(blockNum+1)*blocklen:]
		if validater(modifiedText):
			return modifiedText



#returns the block into which plaintext provided to the oracle is inserted
def findCBCInsertionBlock(oracle, blocklen = 16):
	defaultText = oracle("")
	comparisonText = oracle(chr(0))
	for i in range(len(defaultText)/blocklen):
		if defaultText[i*blocklen:(i+1)*blocklen] != comparisonText[i*blocklen:(i+1)*blocklen]:
			return i


if __name__ == "__main__":
	test = oracle(";admin=true;")
	print validateAdmin(test)
	print validateAdmin(breakValidation(oracle, validateAdmin))