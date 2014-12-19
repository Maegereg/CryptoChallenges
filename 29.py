import hash
import mac

key = "reverie"

#Generates a message MACed with key-prefix SHA-1
def generateMACedMessage():
	global key
	message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
	return (message, mac.sha1KeyPrefix(message, key))

#Checks whether the mac is valid, and if so, whether the message indicates admin access
def checkAdminStatus(message, authenitication):
	global key
	if mac.verifySha1KeyPrefix(message, key, authenitication):
		if ";admin=true" in message:
			return True
	return False

#Returns the message, padded accoridng to the SHA-1 specifications, but as if it haskeylen bytes prepended to it
def padMessageForKeyLength(message, keylen):
	return hash.mdPad((chr(0)*keylen)+message)[keylen:]

#Produces a new message, mac pair valid under the same key as the provided one with the string extension appended
#Validator is a function that returns true if the new mac, message pair is valid (optional: and contains the string extension)
def extendSha1MacedMessage(message, authentication, extension, verifier):
	h4 = authentication & (2**32-1)
	h3 = authentication>>32 & (2**32-1)
	h2 = authentication>>64 & (2**32-1)
	h1 = authentication>>96 & (2**32-1)
	h0 = authentication>>128 & (2**32-1)

	
	guessedKeyLen = 0

	while True:
		#Measured in bytes, not bits
		extraLength = ((len(message)+guessedKeyLen+64)/64)*64
		newMac = hash.sha1(extension, h0, h1, h2, h3, h4, extraLength)
		newMessage = padMessageForKeyLength(message, guessedKeyLen)+extension
		if verifier(newMessage, newMac):
			return (newMessage, newMac)
		guessedKeyLen += 1



if __name__ == "__main__":
	msgMacPair = generateMACedMessage()
	msg = msgMacPair[0]
	authenitication = msgMacPair[1]

	print checkAdminStatus(msg, authenitication)
	extendedMessageMac = extendSha1MacedMessage(msg, authenitication, ";admin=true", checkAdminStatus)
	print checkAdminStatus(extendedMessageMac[0], extendedMessageMac[1])