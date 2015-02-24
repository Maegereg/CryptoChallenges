import dsa, hash, rsa

def recoverKey(k, signature, messageHash, pubKey):
	r, s = signature
	_, q, _, _ = pubKey
	return (((s*k) - messageHash) * rsa.modInverse(r, q)) % q

def bruteForceKey(messageHash, signature, pubKey):
	p, q, g, y = pubKey
	k = 0
	while k < q:

		x = recoverKey(k, signature, messageHash, pubKey)
		testSignature = dsa.signMessageWithK(k, messageHash, x, p, q, g)
		if testSignature == signature:
			return (p, q, g, x)
		k += 1
		if k == 2**16:
			print "HALP"


if __name__ == "__main__":
	message = '''For those that envy a MC it can be hazardous to your health
So be friendly, a matter of life and death, just like a etch-a-sketch'''
	pubKey, privKey = dsa.generateKeys()

	signature, k = dsa.signMessage(message, privKey, leakK = True)

	#Test of key recovery
	assert privKey[3]== recoverKey(k, signature, hash.sha1(message), pubKey)

	#Discover challenge key
	'''
	The provided digest for the message does not match the output of my SHA-1 function 
	or the library SHA-1 function. I have therefore concluded that this is not a problem
	with my implementation.
	'''
	messageHash = 0xd2d0714f014a9784047eaeccf956520045c45265
	signature = (548099063082341131477253921760299949438196259240, 857042759984254168557880549501802188789837994940)

	p, q, g = dsa.STANDARD_PARAMS
	pubKey =(p, q, g, 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17)

	privKey = bruteForceKey(messageHash, signature, pubKey)

	expectedKeyHash = 0x0954edd5e0afe5542a4adf012611a91912a3ec16

	keyHash = hash.sha1(hex(privKey[3])[2:-1])

	print keyHash == expectedKeyHash
