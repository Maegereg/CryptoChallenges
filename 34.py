import aes
import convert
import diffiehellman as dh
import hash

class DHEchoer:
	def sendPublicDHValue(self, A, p, g):
		self.privateKey = dh.generatePrivateKey(p)
		self.sharedSecret = dh.deriveSecret(A, self.privateKey, p)
		self.aesKey = convert.intToByteString(hash.sha1(convert.intToByteString(self.sharedSecret)))[0:16]
		return dh.generatePublicValue(self.privateKey, g, p)

	def sendAESMessage(self, ciphertext, IV):
		plaintext = aes.aesCBCDecrypt(ciphertext, self.aesKey, IV)
		#Same as an IV
		newIV = aes.generateRandomKey()
		newCiphertext = aes.aesCBCEncrypt(plaintext, self.aesKey, newIV)
		return (newCiphertext, newIV)

class DHMITM:
	def __init__(self, realDestination):
		self.realDestination = realDestination

	def sendPublicDHValue(self, A, p, g):
		self.sharedSecret = 0
		self.aesKey = convert.intToByteString(hash.sha1(convert.intToByteString(self.sharedSecret)))[0:16]
		self.realDestination.sendPublicDHValue(p, p, g)
		return p

	def sendAESMessage(self, ciphertext, IV):
		returnMessage, returnIV = self.realDestination.sendAESMessage(ciphertext, IV)

		firstMessage = aes.aesCBCDecrypt(ciphertext, self.aesKey, IV)
		secondMessage = aes.aesCBCDecrypt(returnMessage, self.aesKey, returnIV)

		print firstMessage, secondMessage

		return (returnMessage, returnIV)

if __name__ == "__main__":
	counterPart = DHEchoer()

	privateKey = dh.generatePrivateKey(dh.STANDARD_P)

	publicValue = counterPart.sendPublicDHValue(dh.generatePublicValue(privateKey, dh.STANDARD_G, dh.STANDARD_P), dh.STANDARD_P, dh.STANDARD_G)
	sharedSecret = dh.deriveSecret(publicValue, privateKey, dh.STANDARD_P)

	aesKey = convert.intToByteString(hash.sha1(convert.intToByteString(sharedSecret)))[0:16]
	aesIV = aes.generateRandomKey()

	returnMessage, returnIV = counterPart.sendAESMessage(aes.aesCBCEncrypt("Test Message", aesKey, aesIV), aesIV)
	print aes.aesCBCDecrypt(returnMessage, aesKey, returnIV)

	#Now for the MITM attack

	newCounterpart = DHMITM(counterPart)
	publicValue = newCounterpart.sendPublicDHValue(dh.generatePublicValue(privateKey, dh.STANDARD_G, dh.STANDARD_P), dh.STANDARD_P, dh.STANDARD_G)

	sharedSecret = dh.deriveSecret(publicValue, privateKey, dh.STANDARD_P)

	aesKey = convert.intToByteString(hash.sha1(convert.intToByteString(sharedSecret)))[0:16]
	aesIV = aes.generateRandomKey()

	returnMessage, returnIV = newCounterpart.sendAESMessage(aes.aesCBCEncrypt("Secret Message", aesKey, aesIV), aesIV)
