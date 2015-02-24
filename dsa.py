import hash, rsa
import random 

STANDARD_PARAMS = (0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1,
				   0xf4f47f05794b256174bba6e9b396a7707e563c5b,
				   0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291)

'''
Currently too slow
'''
def generateParameters(L = 2048, N = 224):
	q = rsa.getPrime(N)
	#The smallest L-bit multiple of q
	qMultiple = (pow(2, L)/q+1)*q
	while not rsa.millerRabinTest(qMultiple+1, 100):
		qMultiple += q

	p = qMultiple + 1

	h = 2
	g = 1
	while g == 1:
		h += 1
		g = pow(h, (p-1)*q, p)

	return (p, q, g)

'''
Accepts a set of DSA parameters in a tuple, (p, q, g)
Returns a pair (pubkey, privkey) with the form ((p, q, g, y), (p, q, g, x))
'''
def generateKeys(params = STANDARD_PARAMS):
	p, q, g = params
	#Insecure - should be /dev/urandom
	x = random.randint(1, q-1)
	y = pow(g, x, p)

	return ((p, q, g, y), (p, q, g, x))

def signMessageWithK(k, messageHash, x, p, q, g):
	r = pow(g, k, p)%q
	s = (rsa.modInverse(k, q)* (messageHash + x*r)) % q
	return (r, s)

def signMessage(message, privKey, hashFunction = hash.sha1, leakK = False):
	p, q, g, x = privKey
	k = 0
	r = 0
	s = 0
	while r == 0 or s == 0:
		k = random.randint(1, q-1)
		r, s = signMessageWithK(k, hashFunction(message), x, p, q, g)
	if leakK:
		return ((r, s), k)
	return (r, s)

def verifySignature(message, pubKey, signature, hashFunction = hash.sha1):
	p, q, g, y = pubKey
	r, s = signature
	if r <= 0 or r >= q or s <= 0 or s >= q:
		return False

	w = rsa.modInverse(s, q)
	u1 = (hashFunction(message) * w) % q
	u2 = (r * w) % q
	v = ((pow(g, u1, p)* pow(y, u2, p)) %p ) %q
	return v == r


if __name__ == "__main__":
	message = "test message"
	parameters = STANDARD_PARAMS
	pubKey, privKey = generateKeys(parameters)

	signature = signMessage(message, privKey)

	assert verifySignature(message, pubKey, signature)
	assert not verifySignature(message, pubKey, (signature[0]-1, signature[1]))

