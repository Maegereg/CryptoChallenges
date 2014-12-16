import aes
import xor

class AsciiError(Exception):
	def __init__(self, value):
		self.value = value

	def __str__(self):
		return repr(self.value)

persistentKey = ""

#Encrypts the plaintext with AES in CBC mode with IV = Key
def cbcKIVEncrypt(plaintext, key):
	return aes.aesCBCEncrypt(plaintext, key, key)

#Returns some plaintext encrypted under a random key
def encryptionOracle():
	global persistentKey
	if persistentKey == "":
		persistentKey = aes.generateRandomKey()

	plaintext = 'The West Grestin border checkpoint is now open. Glory to Arstotzka!'
	return cbcKIVEncrypt(plaintext, persistentKey)

#Decrypts the ciphertext, and then checks to make sure all characters are valid ascii. Throws an error if they are not.
def validateCiphertext(ciphertext):
	plaintext = aes.aesCBCDecrypt(ciphertext, persistentKey, persistentKey)
	if len(filter(lambda x: ord(x) > 127 ,plaintext)) > 0:
		raise AsciiError(plaintext)

#Finds the key (probably) when provided with a ciphertext encyrpted under CBC key=IV, and a validator
def findKey(ciphertext, validator, blocklen = 16):
	modifiedCiphertext = ciphertext[0:blocklen]+chr(0)*blocklen+ciphertext[0:blocklen]+ciphertext[2*blocklen:]
	try:
		validator(modifiedCiphertext)
	except AsciiError as e:
		plaintext = e.value
		return xor.xorByteStrings(plaintext[:blocklen], plaintext[2*blocklen:3*blocklen])
	return ""

if __name__ == "__main__":
	ciphertext = encryptionOracle()
	key = findKey(ciphertext, validateCiphertext)
	print key == persistentKey

