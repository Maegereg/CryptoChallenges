import random
import aes
import convert
import string

#import detectecb

#Random 128 bit (16 byte) string
def generateRandomKey():
	return "".join([chr(random.randint(0, 255)) for i in range(16)])

#Also just a random 128 bit string
def generateRandomIV():
	return generateRandomKey()

#Returns the number of blocks that are duplicates of previously existing blocks, and the number of unique blocks that have duplicates, as a tuple
def countDuplicateBlocks(ciphertext, blocklen = 16):
	blocks = {}
	for i in range(len(ciphertext)/blocklen+1):
		block = ciphertext[i*blocklen:(i+1)*blocklen]
		if block not in blocks:
			blocks[block] = 0
		blocks[block] += 1
	return (sum(blocks.values()) - len(blocks), len(filter(lambda x: x>1, blocks.values())))

#Accepts a function that accepts a plaintext and returns a ciphertext
#Returns whether or not that ciphertext was produced using ECB
#TODO: detect block length. maybe?
def determineIfOracleECB(oracle):
	blocklen = 16
	ciphertext = oracle(chr(0)*20*blocklen)
	duplicates = countDuplicateBlocks(ciphertext)
	if duplicates[0] < 18:
		return False
	return True

#Turns out this is not actually what the exercise called for.
'''
Performs a probabalistic calculation to determine if the ciphertext was produced by a cipher operating in
ECB mode. Assumes that things not produced in such a manner will have a random distribution of blocks.
The probability is calculated iteratively and partially to avoid issues with overflow on both the top and bottom of the
fraction. The equation used is Pr <= (c^d)((l-d)^c)(l^d)/(b^(16*d)), where Pr is the probability a sequence
with this many duplicates was produced by a random process, c = the number of unique blocks in the ciphertext
that have more than one occurence, d = the number of duplications of those unique blocks (not counting their 
first appearance), l = the number of blocks in the ciphertext, and b = 2^8 = 256 (note that b^16 = 2^128)

ciphertext is the text to be analyzed
fpRate is a upper bound for the rate at which ciphertexts produced by a random process will be mistaken for 
the product of ECB
blocklen is the size of a block (in bytes) in the ciphertext
'''
def determineIfECB(ciphertext, fpRate = .01, blocklen = 16):
	duplicateBlocks = countDuplicateBlocks(ciphertext, blocklen)
	duplicates = duplicateBlocks[0]
	duplicatedBlocks = duplicateBlocks[1]
	length = len(ciphertext)/blocklen+1

	bottomBase = 256
	bottomExponent = 16*duplicates

	topBases = [duplicatedBlocks, length-duplicates, length]
	topExponents = [duplicates, duplicatedBlocks, duplicates]

	probability = 1.0

	while len(topExponents) > 0 and bottomExponent > 0:
		probability *= topBases[0]
		topExponents[0] -= 1

		if topExponents[0] == 0:
			topExponents.pop(0)
			topBases.pop(0)

		if probability >= 512:
			probability /= bottomBase
			bottomExponent -= 1

	while bottomExponent > 0 and probability > fpRate:
		probability /= bottomBase
		bottomExponent -= 0

	if probability <= fpRate:
		return True
	return False


def getCiphertextEquivalentOfBlock(block, oracle):
	return oracle(block)[:len(block)]


def breakECBOracle(oracle, blocklen = 16):
	ciphertext = oracle("")
	plaintext = ""
	for i in range(len(ciphertext)):
		ciphertextOfInterest = oracle(chr(0)*(blocklen-1-(i%blocklen)))
		blockOfInterest = ciphertextOfInterest[(i/blocklen)*blocklen:(i/blocklen+1)*blocklen]

		previousBlock = plaintext[-blocklen+1:]
		previousBlock = string.rjust(previousBlock, blocklen-1, chr(0))
		for i in range(256):
			if getCiphertextEquivalentOfBlock(previousBlock+chr(i), oracle) == blockOfInterest:
				plaintext += chr(i)
				break
	return plaintext
