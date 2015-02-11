import convert
import math
import padding
import rsa

'''
Uses binary search to find the cube root of a large number
'''
def cubeRoot(k):
	#Start with the builtin python cube root as an approximation
	guess = int(round(math.pow(k, 1.0/3.0)))
	
	low = 0
	high = 0

	#Refine low and high so they actually bracket the root we want
	#We start at guess, and increment guess by naiveCubeRoot(k^3 - guess^3)
	#This ensures that we converge quickly on bracketing values
	if pow(guess, 3) < k:
		high = guess
		while pow(high, 3) < k:
			low = high
			high += int(round(math.pow(k - pow(high, 3), 1.0/3.0)))
	else:
		high = guess
		while pow(high, 3) < k:
			high = low
			low -= int(round(math.pow(pow(high, 3) - k, 1.0/3.0)))

	#If these blow, something is terribly wrong
	assert pow(high, 3) > k
	assert pow(low, 3) < k

	#Vanilla binary search
	while low < high:
		mid = (low+high) // 2
		if pow(mid, 3) < k:
			low = mid
		elif pow(mid, 3) > k:
			high = mid
		else:
			return mid

'''
Accepts a three ciphertexts and the moduluses of their respective public keys
If the plaintexts are all identical, returns the integer form of the plaintext
'''
def extractPlaintext(ctext0, modulus0, ctext1, modulus1, ctext2, modulus2):
	ms0 = modulus1 * modulus2
	ms1 = modulus0 * modulus2
	ms2 = modulus1 * modulus0

	N = modulus0 * modulus1 * modulus2

	result = ((ctext0 * ms0 * rsa.modInverse(ms0, modulus0)) +
	         (ctext1 * ms1 * rsa.modInverse(ms1, modulus1)) +
			 (ctext2 * ms2 * rsa.modInverse(ms2, modulus2))) % N
	return cubeRoot(result)

if __name__ == "__main__":
	plaintext = "This is good"

	pubkey0, _ = rsa.keygen()
	pubkey1, _ = rsa.keygen()
	pubkey2, _ = rsa.keygen()

	ctext0 = rsa.encodeCiphertext(rsa.encryptString(plaintext, pubkey0), pubkey0)
	ctext1 = rsa.encodeCiphertext(rsa.encryptString(plaintext, pubkey1), pubkey1)
	ctext2 = rsa.encodeCiphertext(rsa.encryptString(plaintext, pubkey2), pubkey2)

	newplaintext = extractPlaintext(ctext0[0], pubkey0[1], ctext1[0], pubkey1[1], ctext2[0], pubkey2[1])

	newTextPlaintext = padding.stripPkcs7(convert.intToByteString(newplaintext))
	
	print newTextPlaintext == plaintext

