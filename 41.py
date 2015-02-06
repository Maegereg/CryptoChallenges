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
		self.e, self.d, self.n = rsa.keygen()

	'''
	Performs a decryption on the ciphertext. Returns either the encoded plaintext
	(as a list of integers, which, when converted to strings and joined become the 
	full plaintext), or an empty string if the message has already been decrypted
	'''
	def decrypt(self, ciphertext):
		hashValue = hash.sha256("".join(map(str, ciphertext)))
		if hashValue in self.prevMessages:
			return ""
		else:
			self.prevMessages.add(hashValue)
			#We can't just combine back to a string because the math wouldn't work
			return map(lambda x: rsa.decryptInt(x, self.d, self.n), ciphertext)

	'''
	Generate an encrypted message that can't just be decrypted
	'''
	def getMessage(self):
		message = "message too long for single encoding"
		toReturn = rsa.encryptString(message, self.e, self.n)
		#So it can't just be decrypted
		self.decrypt(toReturn)
		return toReturn

	'''
	Returns the public key as an (e, n) pair
	'''
	def getPublicKey(self):
		return (self.e, self.n)

'''
Modifies a ciphertext so that it will decrypt to a value that allows recovery of the plaintext
Returns the new ciphertext, and the S used to produce it
'''
def generateModifiedCiphertext(ciphertext, publicExponent, modulus):
	S = random.randint(2, modulus-1)
	#Ciphertext is actually a list of ciphertexts
	newCtext = map(lambda x: (pow(S, publicExponent, modulus)*x)%modulus, ciphertext)
	return (newCtext, S)

'''
Given an oracle and a ciphertext, but assuming we can't just ask the oracle to decrypt the 
ciphertext, modifies the ciphertext, decrypts it and recovers the plaintext
'''
def decryptCiphertext(ciphertext, oracle):
	e, n = oracle.getPublicKey()
	newCtext, S = generateModifiedCiphertext(ciphertext, e, n)
	newPlaintext = oracle.decrypt(newCtext)

	inverseS = rsa.modInverse(S, n)
	encodedPlainText = map(lambda x: (x*inverseS)%n, newPlaintext)
	return "".join(map(convert.intToByteString, encodedPlainText))



if __name__ == "__main__":
	oracle = RSAOracle()
	message = oracle.getMessage()
	#We can't just decrypt the message
	print oracle.decrypt(message) == ""
	print decryptCiphertext(message, oracle)