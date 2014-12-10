from ecboracle import *

#Encrypts a given plaintext using AES with ECB or CBC randomly chosen
#Key and IV (if necessary) are chosen at random
#Plaintext is padded with 5-10 bytes at beginning and end
def encryptRandomly(plaintext):
	padding = generateRandomIV()
	paddedText = padding[:random.randint(5, 10)]+plaintext+padding[random.randint(-10, -5):]
	if random.random() >= 0.5:
		#Encrypt under ECB
		return aes.aesECBEncrypt(paddedText, generateRandomKey())
	else:
		#Encrypt under CBC
		return aes.aesCBCEncrypt(paddedText, generateRandomKey(), generateRandomIV())

if __name__ == "__main__":
	for i in range(10):
		print "ECB" if determineIfOracleECB(encryptRandomly) else "CBC"