import aes
import convert
import diffiehellman as dh
import hash

def getAESKeyFromSharedSecret(sharedSecret):
	return convert.convertToByteString(hash.sha1(convert.convertToByteString(sharedSecret)))[0:16]

class DHEchoer:
	def sendGroupParameters(self, p, g):
		self.p = p
		self.g = g
		return "ACK"

	def sendPublicDHValue(self, A):
		self.privateKey = dh.generatePrivateKey(self.p)
		self.sharedSecret = dh.deriveSecret(A, self.privateKey, self.p)
		self.aesKey = getAESKeyFromSharedSecret(self.sharedSecret)
		return dh.generatePublicValue(self.privateKey, self.g, self.p)

	def sendAESMessage(self, ciphertext, IV):
		try:
			plaintext = aes.aesCBCDecrypt(ciphertext, self.aesKey, IV)
		except Exception:
			plaintext = "Invalid Message"
		#Same as an IV
		newIV = aes.generateRandomKey()
		newCiphertext = aes.aesCBCEncrypt(plaintext, self.aesKey, newIV)
		return (newCiphertext, newIV)

class PAlteringDHMITM:
	#Accepts either a value to replace P with, or a function to derive the value, 
	#and a list of resulting shared secret values
	def __init__(self, realDestination, newG, expectedSecrets):
		self.realDestination = realDestination
		self.newG = newG
		self.expectedSecrets = expectedSecrets

	def sendGroupParameters(self, p, g):
		if type(self.newG) == type(g):
			gToSend = self.newG
		else:
			gToSend = self.newG(p)
		return self.realDestination.sendGroupParameters(p, gToSend)


	def sendPublicDHValue(self, A):
		return self.realDestination.sendPublicDHValue(A)

	def sendAESMessage(self, ciphertext, IV):
		returnMessage, returnIV = self.realDestination.sendAESMessage(ciphertext, IV)
		#We can only decipher the message from A to B, because that's the only version of the shared secret that has the tampered g value
		maxCount = 0
		maxMessage = ""
		for possibleSecret in self.expectedSecrets:
			tempAESKey = getAESKeyFromSharedSecret(possibleSecret)
			try:
				possiblePlaintext = aes.aesCBCDecrypt(ciphertext, tempAESKey, IV)
				if len(filter(str.isalpha, possiblePlaintext)) > maxCount:
					maxCount = len(filter(str.isalpha, possiblePlaintext))
					maxMessage = possiblePlaintext
			except Exception as e:
				continue
		print maxMessage
		return (returnMessage, returnIV)


if __name__ == "__main__":
	counterPart = DHEchoer()

	privateKey = dh.generatePrivateKey(dh.STANDARD_P)

	counterPart.sendGroupParameters(dh.STANDARD_P, dh.STANDARD_G)

	publicValue = counterPart.sendPublicDHValue(dh.generatePublicValue(privateKey, dh.STANDARD_G, dh.STANDARD_P))
	sharedSecret = dh.deriveSecret(publicValue, privateKey, dh.STANDARD_P)

	aesKey = convert.convertToByteString(hash.sha1(convert.convertToByteString(sharedSecret)))[0:16]
	aesIV = aes.generateRandomKey()

	returnMessage, returnIV = counterPart.sendAESMessage(aes.aesCBCEncrypt("Test Message", aesKey, aesIV), aesIV)
	print aes.aesCBCDecrypt(returnMessage, aesKey, returnIV)

	#Now for the MITM attack
	# g = 1

	newCounterpart = PAlteringDHMITM(counterPart, 1, [1])

	newCounterpart.sendGroupParameters(dh.STANDARD_P, dh.STANDARD_G)

	publicValue = newCounterpart.sendPublicDHValue(dh.generatePublicValue(privateKey, dh.STANDARD_G, dh.STANDARD_P))

	sharedSecret = dh.deriveSecret(publicValue, privateKey, dh.STANDARD_P)

	aesKey = convert.convertToByteString(hash.sha1(convert.convertToByteString(sharedSecret)))[0:16]
	aesIV = aes.generateRandomKey()

	returnMessage, returnIV = newCounterpart.sendAESMessage(aes.aesCBCEncrypt("Secret Message", aesKey, aesIV), aesIV)

	# g = p

	newCounterpart = PAlteringDHMITM(counterPart, lambda x: x, [0])

	newCounterpart.sendGroupParameters(dh.STANDARD_P, dh.STANDARD_G)

	publicValue = newCounterpart.sendPublicDHValue(dh.generatePublicValue(privateKey, dh.STANDARD_G, dh.STANDARD_P))

	sharedSecret = dh.deriveSecret(publicValue, privateKey, dh.STANDARD_P)

	aesKey = convert.convertToByteString(hash.sha1(convert.convertToByteString(sharedSecret)))[0:16]
	aesIV = aes.generateRandomKey()

	returnMessage, returnIV = newCounterpart.sendAESMessage(aes.aesCBCEncrypt("Secret Message 2", aesKey, aesIV), aesIV)

	# g = p-1

	newCounterpart = PAlteringDHMITM(counterPart, lambda x: x-1, [1, dh.STANDARD_P-1])

	newCounterpart.sendGroupParameters(dh.STANDARD_P, dh.STANDARD_G)

	publicValue = newCounterpart.sendPublicDHValue(dh.generatePublicValue(privateKey, dh.STANDARD_G, dh.STANDARD_P))

	sharedSecret = dh.deriveSecret(publicValue, privateKey, dh.STANDARD_P)

	aesKey = convert.convertToByteString(hash.sha1(convert.convertToByteString(sharedSecret)))[0:16]
	aesIV = aes.generateRandomKey()

	returnMessage, returnIV = newCounterpart.sendAESMessage(aes.aesCBCEncrypt("Secret Message 3", aesKey, aesIV), aesIV)
