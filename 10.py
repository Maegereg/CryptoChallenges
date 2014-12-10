from aes import *

if __name__ == "__main__":
	inputFile = open("10.txt")
	ciphertext = ""
	for line in inputFile:
		ciphertext += convert.b64ToByteString(line.lstrip().rstrip())
	plaintext = aesCBCDecrypt(ciphertext, "YELLOW SUBMARINE", chr(0)*AES_BLOCK_SIZE)
	print plaintext
	print "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	testEncryption = aesCBCEncrypt(plaintext, "YELLOW_SUBMARINE", chr(1)*AES_BLOCK_SIZE)
	consistencyCheck = aesCBCDecrypt( testEncryption , "YELLOW_SUBMARINE", chr(1)*AES_BLOCK_SIZE)
	print consistencyCheck
	