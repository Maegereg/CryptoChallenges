import sys
import englishscore
import convert

#Message: "Now that the party is jumping"
#Ciphertext: 7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f
def ex4():
	filename = "gistfile1.txt"
	inputFile = open(filename)
	bestScore = sys.maxint
	bestMessage = ""
	bestLine = ""
	for line in inputFile:
		key = englishscore.findSingleXorKeyForHex(line.rstrip())
		if key[2] < bestScore:
			bestScore = key[2]
			bestMessage = key[1]
			bestLine = line.rstrip()
	print "Line: "+bestLine
	print "Message: "+bestMessage
	inputFile.close()

if __name__ == "__main__":
	ex4()