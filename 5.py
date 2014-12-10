import englishscore
import convert

def repeatingXorEncrypt(key, message):
	return convert.byteStringToHex(englishscore.repeatedXor(key, message))

def ex5():
	message = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	key = "ICE"
	print repeatingXorEncrypt(key, message)

if __name__ == "__main__":
	ex5()