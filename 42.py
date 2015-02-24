import convert
import decimal as dec
import hash
import math
import rsa

class SignatureChecker:
	def __init__(self):
		self.pubKey, self.privkey = rsa.keygen()

	def checkSignature(self, signature, message):
		return rsa.checkSignature(message, signature, self.pubKey)

	def getPubKey(self):
		return self.pubKey

'''
Based on the nth root algorithm derived from Newton's method
(https://en.wikipedia.org/wiki/Nth_root_algorithm)
Returns the integer root (the largest integer x for with x**n <= k)
'''
def nthRoot(k, n):
	x = k
	y = (x+1) // 2
	while y < x:
		x = y
		y = ((n-1)*x + k // pow(x, n-1)) // n
	return x

'''
First, the cube root approach
'''
def forgeSignature(message, pubKey, hashFunction=hash.sha256):
	if pubKey[0] != 3:
		raise Exception("Cannot forge a signature for e != 3")

	blockLen = rsa.getBlocklen(pubKey)

	digest = convert.intToByteString(hashFunction(message))

	passableSignature = chr(0)+chr(1)+chr(0xff)+chr(0)+digest

	passableSignature = passableSignature.ljust(blockLen, chr(0))

	integerValue = convert.byteStringToInt(passableSignature)
	root = nthRoot(integerValue, 3)
	if root**3 == integerValue:
		toReturn = root
	else:
		toReturn = root+1
	return rsa.decodeCiphertext([toReturn], pubKey)

	
'''
Approach based on Bleichenbacher's math
Currently broken
'''
def alternateForgeSignature(message, pubKey, hashFunction=hash.sha256):
	if pubKey[0] != 3:
		raise Exception("Cannot forge a signature for e != 3")

	blockLen = rsa.getBlocklen(pubKey)
	digestInt = hashFunction(message)

	hashLen = len(chr(0)+convert.intToByteString(digestInt))*8
	bitLen = blockLen*8

	dec.getcontext().prec = bitLen

	N = pow(2, hashLen) - digestInt

	cubeRoot = dec.Decimal(2)** (dec.Decimal(bitLen-15)/dec.Decimal(3.0)) - dec.Decimal(N) * dec.Decimal(2)**(dec.Decimal(bitLen-24-hashLen) - dec.Decimal((bitLen-15)*2)/dec.Decimal(3))

	print repr(convert.intToByteString(digestInt))
	print repr(convert.intToByteString(pow(int(cubeRoot), 3)))

	return rsa.decodeCiphertext([cubeRoot], pubKey)


if __name__ == "__main__":
	message = "hi mom"
	pubKey, _ = rsa.keygen()
	fakeSignature = forgeSignature(message, pubKey)
	print rsa.flawedCheckSignature(message, fakeSignature, pubKey)