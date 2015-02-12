import convert
import hash
import random
import rsa

'''
Stores a set of RSA keys and performs encryption and decryption.
However, each ciphertext can only be decrypted once.
'''
class RSAOracle:
	def __init__(self):
		self.prevMessages = set()
		self.pubkey, self.privkey = rsa.keygen()

	'''
	Performs a decryption on the ciphertext. Returns either the plaintext, 
	or an empty string if the message has already been decrypted
	Accepts the encoded form of the ciphertext, not the string form,
	and returns the encoded form of the plaintext, not the string form
	'''
	def decrypt(self, ciphertext):
		hashValue = hash.sha256(rsa.decodeCiphertext(ciphertext, self.pubkey))
		if hashValue in self.prevMessages:
			return ""
		else:
			self.prevMessages.add(hashValue)
			return map(lambda x: rsa.decryptInt(x, self.privkey), ciphertext)

	'''
	Generate an encrypted message that can't just be decrypted.
	Returns the encoded form of the ciphertext
	'''
	def getMessage(self):
		message = "message"
		toReturn = rsa.encryptString(message, self.pubkey)
		toReturn = rsa.encodeCiphertext(toReturn, self.pubkey)
		#So it can't just be decrypted
		self.decrypt(toReturn)
		return toReturn

	'''
	Returns the public key as an (e, n) pair
	'''
	def getPublicKey(self):
		return self.pubkey

'''
Modifies a ciphertext so that it will decrypt to a value that allows recovery of the plaintext
Accepts a encoded Ciphertext (a list of ints)
Returns the new encoded ciphertext, and the S used to produce it
'''
def generateModifiedCiphertext(ciphertext, publicExponent, modulus):
	S = random.randint(2, modulus-1)
	#Ciphertext is actually a list of ciphertexts
	newCtext = map(lambda x: (pow(S, publicExponent, modulus)*x)%modulus, ciphertext)
	return (newCtext, S)

'''
Given an oracle and a ciphertext, but assuming we can't just ask the oracle to decrypt the 
ciphertext, modifies the ciphertext, decrypts it and recovers the plaintext
Accepts an encoded ciphertext (list of ints)
'''
def decryptCiphertext(ciphertext, oracle):
	e, n = oracle.getPublicKey()
	
	newCtext, S = generateModifiedCiphertext(ciphertext, e, n)

	newPlaintext = oracle.decrypt(newCtext)

	inverseS = rsa.modInverse(S, n)
	encodedPlaintext = map(lambda x: (x*inverseS)%n, newPlaintext)

	return rsa.decodePlaintext(encodedPlaintext, oracle.getPublicKey())



if __name__ == "__main__":
	oracle = RSAOracle()
	message = oracle.getMessage()
	#We can't just decrypt the message
	print oracle.decrypt(message) == ""
	print repr(decryptCiphertext(message, oracle))