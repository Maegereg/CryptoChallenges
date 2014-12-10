from englishscore import *

#Message: "Cooking MC's like a pound of bacon"
#Key: X
if __name__ == "__main__":
	message = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	key = findSingleXorKeyForHex(message)
	print "Message: "+key[1]
	print "Key: "+key[0]