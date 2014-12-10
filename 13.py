from kvparser import *

def create_admin_profile(profileOracle):
	if ecboracle.determineIfOracleECB(profileOracle):
		#Was going to break the plaintext so this wouldn't have to be a known plaintext attack, but that's hard to do given that the oracle won't encrypt two characters
		#predicateLength = findPrefixLength(profileOracle, 16)
		#tempOracle = lambda ptext: profileOracle((16-(predicateLength%16))*chr(0)+ptext)[16*(predicateLength/16+1):]
		#plaintext = ecbdecrypter.breakECBOracle( tempOracle)

		predicateLength = findPrefixLength(profileOracle, 16)
		suffixLength = findSuffixLength(profileOracle, predicateLength, 16)
		charsToInsert = 16 - (predicateLength+suffixLength - len('user'))%16
		cipherTextToModify = profileOracle(chr(0)*charsToInsert)
		blockToInsert = profileOracle((16-(predicateLength%16))*chr(0)+aes.padForAES('admin'))[16*(predicateLength/16+1):16*(predicateLength/16+2)]
		return cipherTextToModify[:-16]+blockToInsert

#Determines how many bytes are prepended to the provided plaintext by the given encryption function
def findPrefixLength(profileOracle, blocksize=16):
	charsToAppend = 2*blocksize
	firstDoubledBlock = -1
	while firstDoubledBlock < 0:
		charsToAppend += 1
		firstDoubledBlock = getDoubleBlocksIndex(profileOracle(charsToAppend*chr(0)))
		if (charsToAppend > 50):
			break
	return blocksize*firstDoubledBlock - charsToAppend + 2*blocksize

#Determines how many bytes are appended to the plaintext by the given encryption function, given that the lenght of the predicate is known
def findSuffixLength(profileOracle, predicateLength, blocksize=16):
	defaultLength = len(profileOracle(""))
	charsToAppend = 1
	while len(profileOracle(charsToAppend*chr(0))) == defaultLength:
		charsToAppend += 1
	return defaultLength - predicateLength - charsToAppend

#Searches a given ciphertext for the first instance of two blocks of a given length with the same value
def getDoubleBlocksIndex(ciphertext, blocksize=16):
	cipherBlocks = getBlocks(ciphertext, blocksize)
	for i in range(len(cipherBlocks)):
		if i < len(cipherBlocks)-1 and cipherBlocks[i] == cipherBlocks[i+1]:
			return i
	return -1

#Returns the input string divided into a list of blocks of characters of the given length
def getBlocks(ciphertext, blocksize=16):
	return [ciphertext[i*blocksize:(i+1)*blocksize] for i in range(len(ciphertext)/blocksize)]

if __name__ == "__main__":
	global persistentKey
	print create_admin_profile(encrypted_profile_for)
	print repr(decrypt_profile(create_admin_profile(encrypted_profile_for)).serialize())