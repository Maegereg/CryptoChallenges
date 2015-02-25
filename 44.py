import dsa, hash, rsa

def recoverKey(k, signature, messageHash, pubKey):
	r, s = signature
	_, q, _, _ = pubKey
	return (((s*k) - messageHash) * rsa.modInverse(r, q)) % q

def extractK(message1, signature1, message2, signature2, pubKey):
	_, q, _, _ = pubKey
	_, s1 = signature1
	_, s2 = signature2
	sDifference = (s1 - s2) % q
	mDifference = (message1 - message2) % q

	return (rsa.modInverse(sDifference, q) * mDifference) % q



if __name__ == "__main__":
	p, q, g = dsa.STANDARD_PARAMS
	pubKey = (p, q, g, 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821)

	#Parse input file into messages and signatures
	inFile = open("44.txt")
	signedMessages = []
	s = 0
	r = 0
	for line in inFile:
		splitLine = line.split(":")
		if splitLine[0] == 's':
			s = int(splitLine[1])
		elif splitLine[0] == 'r':
			r = int(splitLine[1])
		elif splitLine[0] == 'm':
			signature = (r, s)
			message = int(splitLine[1], 16)
			signedMessages.append((message, signature))

	#Find a pair of messages with matching r - indicates same k
	firstMessage = None
	secondMessage = None
	for message1 in signedMessages:
		for message2 in signedMessages:
			if message1 != message2:
				#If identical r
				if message1[1][0] == message2[1][0]:
					firstMessage = message1
					secondMessage = message2
					break
		if firstMessage is not None:
			break

	sharedK = extractK(firstMessage[0], firstMessage[1], secondMessage[0], secondMessage[1], pubKey)

	privKey = recoverKey(sharedK, firstMessage[1], firstMessage[0], pubKey)

	expectedKeyHash = 0xca8f6f7c66fa362d40760d135b763eb8527d3d52

	keyHash = hash.sha1(hex(privKey)[2:-1])

	print keyHash == expectedKeyHash




