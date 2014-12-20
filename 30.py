import hash
import mac

key = "reverie"

#Generates a message MACed with key-prefix SHA-1
def generateMACedMessage():
	global key
	message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
	return (message, mac.md4KeyPrefix(message, key))

#Checks whether the mac is valid, and if so, whether the message indicates admin access
def checkAdminStatus(message, authenitication):
	global key
	if mac.verifyMd4KeyPrefix(message, key, authenitication):
		if ";admin=true" in message:
			return True
	return False

#Returns the message, padded accoridng to the SHA-1 specifications, but as if it haskeylen bytes prepended to it
def padMessageForKeyLength(message, keylen):
	return hash.mdPad((chr(0)*keylen)+message, bigEndian = False)[keylen:]

#Produces a new message, mac pair valid under the same key as the provided one with the string extension appended
#Validator is a function that returns true if the new mac, message pair is valid (optional: and contains the string extension)
def extendMd4MacedMessage(message, authentication, extension, verifier):
	d = hash.reverseBytes(authentication & (2**32-1))
	c = hash.reverseBytes(authentication>>32 & (2**32-1))
	b = hash.reverseBytes(authentication>>64 & (2**32-1))
	a = hash.reverseBytes(authentication>>96 & (2**32-1))

	
	guessedKeyLen = 7

	#while True:
		#Measured in bytes, not bits
	extraLength = ((len(message)+guessedKeyLen+64)/64)*64
	newMac = hash.md4(extension, a, b, c, d, extraLength)
	newMessage = padMessageForKeyLength(message, guessedKeyLen)+extension
	if verifier(newMessage, newMac):
		return (newMessage, newMac)
	#guessedKeyLen += 1



if __name__ == "__main__":
	msgMacPair = generateMACedMessage()
	msg = msgMacPair[0]
	authenitication = msgMacPair[1]

	print checkAdminStatus(msg, authenitication)
	extendedMessageMac = extendMd4MacedMessage(msg, authenitication, ";admin=true", checkAdminStatus)
	print checkAdminStatus(extendedMessageMac[0], extendedMessageMac[1])