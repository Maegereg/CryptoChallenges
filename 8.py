import convert
import math

'''
Encrypted buffer:

d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a
'''

#Get the frequency of all the bytes in the input
def getLetterFrequencies(inputString):
	frequencies = {}
	for char in inputString:
		if char not in frequencies:
			frequencies[char] = 0
		frequencies[char] += 1.0/len(inputString)
	return frequencies

#Return a sum of the difference of each letter's frequency and it's expected frequency
def getFrequencyScore(inputString):
	frequencies = getLetterFrequencies(inputString)
	score = 0
	for char in frequencies:
		score += math.fabs(frequencies[char] - 1.0/len(frequencies))
	return score

#Find the ECB encrypted buffer (the one with the least random byte distribution)
if __name__ == "__main__":
	inFile = open("aesbuffers.txt")
	cipherTexts = []
	for line in inFile:
		cipherTexts.append(convert.hexToByteString(line.replace("\n", "")))
	inFile.close()

	bestLine = ""
	bestScore = 0
	for cipherText in cipherTexts:
		score = getFrequencyScore(cipherText)
		if score > bestScore:
			bestScore = score
			bestLine = cipherText
	print convert.byteStringToHex(bestLine)
	print bestScore