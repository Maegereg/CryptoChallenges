import sys
import math
import xor
import convert

#Character frequencies in the default file drawn from http://www.data-compression.com/english.html
#Reads in a csv file where each line corresponds to a letter with the format letter, frequency
#Frequencies should be between 0 and 1 and add up to 1
def getStandardFrequencies(filename = "letterfrequencies.csv"):
	frequenciesTable = {}
	frequenciesFile = open(filename)
	for line in frequenciesFile:
		splitline = line.split(",")
		frequenciesTable[splitline[0]] = float(splitline[1])
	return frequenciesTable


#Asigns a numerical score to a string that should indicate the likelihood that it is english (lower is better)
#Based on the frequency of characters appearing in the string
def englishScore(string):
	frequencyTable = {}
	for char in string:
		#Rule out any string with a non-printing character - 10 and 13 are \n and \r
		if ((ord(char) < 32 and (ord(char) != 10 and ord(char) != 13)) or ord(char) > 126):
			return sys.maxint
 		if char not in frequencyTable:
			frequencyTable[char] = 0
		frequencyTable[char] += 1

	standardFrequency = getStandardFrequencies()
	score = 0
	for char in frequencyTable:
		if char.lower() in standardFrequency:
			score += math.fabs(frequencyTable[char]/len(string) - standardFrequency[char.lower()])**2
		else:
			score += frequencyTable[char]
	return score

#Xor the key with the message, repeating the key as many times as necessary to reach the message length	
def repeatedXor(key, message):
	return xor.xorByteStrings(message, (key*( len(message)/len(key) +1))[0:len(message)])

#Finds the best repeating-xor key for a message
#Returns a 3-tuple of the key, the decoded message, and the englishscore
def findSingleXorKey(message):
	bestKey = ""
	bestDecode = ""
	bestScore = sys.maxint
	for char in range(256):
		decodeAttempt = repeatedXor(chr(char), message)
		score = englishScore(decodeAttempt)
		if (score < bestScore):
			bestScore = score
			bestKey = chr(char)
			bestDecode = decodeAttempt
	return (bestKey, bestDecode, bestScore)

def findSingleXorKeyForHex(hexMessage):
	return findSingleXorKey(convert.hexToByteString(hexMessage))
