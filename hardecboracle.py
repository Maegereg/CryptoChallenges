import random
import aes
import convert
import string

import ecboracle

AESKey = ""

UNKNOWN_STRING = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

#Encrypts the plaintext with a persistent AES key in ECB mode
#Prepends a random number of random bytes to the plaintext, and appends a plaintext
def encryptionBlackBox(plaintext):
	global AESKey
	if AESKey == "":
		AESKey = ecboracle.generateRandomKey()

	charsToAdd = random.randint(0, 32)
	#print charsToAdd, 
	fullPlaintext = "".join([chr(random.randint(0, 255)) for x in range(charsToAdd)])+plaintext+convert.b64ToByteString(UNKNOWN_STRING)
	return aes.aesECBEncrypt(fullPlaintext, AESKey)


#Uses the oracle to determine the encrypted equivalent of the given block
#Can also be supplied with less than a full block to obtain part of the plaintext
def getCiphertextEquivalentOfBlock(block, oracle, blocklen=16):
	return getCiphertextBlock(block, oracle, 0)

#Returns the numbered block from the ciphertext, with the given plaintext submitted and the random predicate ignored
def getCiphertextBlock(plaintextToAdd, oracle, blocknum, blocklen=16):
	paddedCiphertext = ""
	doubleBlocksIndex = -1
	while doubleBlocksIndex < 0:
		paddedCiphertext = oracle((2*blocklen*chr(0))+plaintextToAdd)
		doubleBlocksIndex = getDoubleBlocksIndex(paddedCiphertext)
	return paddedCiphertext[(doubleBlocksIndex+2+blocknum)*blocklen:(doubleBlocksIndex+3+blocknum)*blocklen]

def breakECBOracle(oracle, blocklen = 16):
	paddedCiphertext = ""
	doubleBlocksIndex = -1
	while doubleBlocksIndex < 0:
		paddedCiphertext = oracle(2*blocklen*chr(0))
		doubleBlocksIndex = getDoubleBlocksIndex(paddedCiphertext)
	ciphertext = paddedCiphertext[(doubleBlocksIndex+2)*blocklen:]

	plaintext = ""
	i = 0
	possiblePadding = False
	#It's possible to go through an iteration of the loop and not correctly find the next character of the plaintext
	#This is because certain random padding can be mistaken for part of the double blocks that delineate the end of the padding,
	#leading to the wrong block being retrieved as either the block of interest or one of the potential matches
	#When this happens, we won't discover a letter of the plaintext, so we'll re-try the same letter until different random padding appears
	while i < len(ciphertext):
		blockOfInterest = getCiphertextBlock(chr(1)*(blocklen-1-(i%blocklen)), oracle, i/16)

		previousBlock = plaintext[-blocklen+1:]
		previousBlock = string.rjust(previousBlock, blocklen-1, chr(1))
		for j in range(256):
			if getCiphertextEquivalentOfBlock(previousBlock+chr(j), oracle) == blockOfInterest:
				plaintext += chr(j)
				#If we've found a letter, go to the next one, otherwise retry
				i += 1
				break
			#If we may have found padding at the end of the message, check
			elif j == 255 and plaintext[-1] == chr(1):
				possiblePadding = True
				plaintext = plaintext[:-1]+chr(2)
			elif j == 255 and possiblePadding:
				#It's definitely padding, so we can exit the loop
				if plaintext[-1] == chr(2) and plaintext[-2] == chr(2):
					return plaintext
				#It's not padding, so we need to undo the changes and try again.
				else:
					plaintext = plaintext[:-1] + chr(1)
					possiblePadding = False
	return plaintext

#Searches a given ciphertext for the first instance of two blocks of a given length with the same value
def getDoubleBlocksIndex(ciphertext, blocksize=16):
	cipherBlocks = getBlocks(ciphertext, blocksize)
	for i in range(len(cipherBlocks)):
		if i < len(cipherBlocks)-1 and cipherBlocks[i] == cipherBlocks[i+1]:
			if i < len(cipherBlocks) -2 and cipherBlocks[i] == cipherBlocks[i+2]:
				print "Yass"
			return i
	return -1

#Returns the input string divided into a list of blocks of characters of the given length
def getBlocks(ciphertext, blocksize=16):
	return [ciphertext[i*blocksize:(i+1)*blocksize] for i in range(len(ciphertext)/blocksize)]
