import aes
import convert
import ecboracle
import string
import xor

def generateCiphertexts():
	plaintexts = ["SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==", 
	"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=", 
	"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==", 
	"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=", 
	"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk", 
	"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==", 
	"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=", 
	"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==", 
	"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=", 
	"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl", 
	"VG8gcGxlYXNlIGEgY29tcGFuaW9u", 
	"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==", 
	"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=", 
	"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==", 
	"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=", 
	"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=", 
	"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==", 
	"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==", 
	"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==", 
	"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==", 
	"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==", 
	"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==", 
	"U2hlIHJvZGUgdG8gaGFycmllcnM/", 
	"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=", 
	"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=", 
	"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=", 
	"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=", 
	"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==", 
	"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==", 
	"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=", 
	"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==", 
	"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu", 
	"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=", 
	"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs", 
	"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=", 
	"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0", 
	"SW4gdGhlIGNhc3VhbCBjb21lZHk7", 
	"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=", 
	"VHJhbnNmb3JtZWQgdXR0ZXJseTo=", 
	"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="]
	plaintexts = map(convert.b64ToByteString, plaintexts)
	key = ecboracle.generateRandomKey()
	return map(lambda x: aes.aesCTREncrypt(x, key, 0), plaintexts)

def findNgrams(ciphertexts, n, threshold = 1):
	Ngrams = []
	maxLength = getMaxLength(ciphertexts)
	for i in range(maxLength-n+1):
		ngramsAtIndex = {}
		for j in range(len(ciphertexts)):
			curNgram = ciphertexts[j][i:i+n]
			if curNgram in ngramsAtIndex:
				ngramsAtIndex[curNgram].append(j)
			else:
				ngramsAtIndex[curNgram] = [j]
		for ngram in ngramsAtIndex:
			if len(ngramsAtIndex[ngram]) > threshold and len(ngram) == n :
				Ngrams.append((i, ngram, ngramsAtIndex[ngram]))
	return sorted(Ngrams, key=lambda x: len(x[2]))

def findTrigrams(ciphertexts, threshold = 1):
	return findNgrams(ciphertexts, 3, threshold)

def findFrequentLetters(ciphertexts, threshold = 1):
	return findNgrams(ciphertexts, 1, threshold)

def getMaxLength(ciphertexts):
	return max(map(len, ciphertexts))

def printGuesses(ciphertexts, keystream):
	print "     "+" ".join([string.rjust(repr( x ), 2) for x in range(len(keystream))])
	print " k   "+" ".join([string.rjust(repr( keystream[x])[1:-1].replace("\\x", ""), 2) for x in range(len(keystream))])
	for i in range(len(ciphertexts)):
		print string.rjust(str(i), 2)+"   "+" ".join([string.rjust(repr( chr(ord(ciphertexts[i][x])^ord(keystream[x])) )[1:-1].replace("\\x", ""), 2) for x in range(len(ciphertexts[i]))])

def tryCrib(plaintextCrib, position, ciphertextsWithGuess, ciphertexts, keystream):
	tempKeyStream = list(keystream)
	guessKeyBytes = ciphertexts[ciphertextsWithGuess[0]][position:position+len(plaintextCrib)]
	guessKeyBytes = list(xor.xorByteStrings(guessKeyBytes, plaintextCrib))
	tempKeyStream[position:position+len(plaintextCrib)] = guessKeyBytes
	printGuesses(ciphertexts, tempKeyStream)
	keep = raw_input("Accept guess? (y/n) ")
	if keep == "y":
		keystream[position:position+len(plaintextCrib)] = guessKeyBytes
		return True
	return False


if __name__ == "__main__":
	ciphertexts = generateCiphertexts()
	maxLength = getMaxLength(ciphertexts)
	keystream = [chr(0)]*maxLength
	
	frequentLetters = findFrequentLetters(ciphertexts, 8)
	for letter in frequentLetters:
		printGuesses(ciphertexts, "".join(keystream))
		print "Letter "+repr(letter[1])+" at position "+str(letter[0])+" in ciphertexts "+repr(letter[2])
		guess = raw_input("Guess plaintext?")
		while guess != "":
			if tryCrib(guess, letter[0], letter[2], ciphertexts, keystream):
				guess = ""
			else:
				guess = raw_input("Guess plaintext?")

	trigrams = findTrigrams(ciphertexts, 2)
	for trigram in trigrams:
		printGuesses(ciphertexts, "".join(keystream))
		print "Trigram "+repr(trigram[1])+" at position "+str(trigram[0])+" in ciphertexts "+repr(trigram[2])
		guess = raw_input("Guess plaintext?")
		while guess != "":
			if tryCrib(guess, trigram[0], trigram[2], ciphertexts, keystream):
				guess = ""
			else:
				guess = raw_input("Guess plaintext?")

	guess = raw_input("Make a guess (position,ciphertext,guess) or quit (quit): ")
	while guess != "quit":
		splitGuess = guess.split(",")
		tryCrib(splitGuess[2], int(splitGuess[0]), [int(splitGuess[1])], ciphertexts, keystream)
		guess = raw_input("Make a guess (position,ciphertext,guess) or quit (quit): ")


''' 
 ciphertexts:
 I have met them at close of day
 Coming with vivid faces
 From counter or desk among grey
 Eighteenth-century houses.
 I have passed with a nod of the head
 Or polite meaningless words,
 Or have lingered a while and said
 Polite meaningless words,
 And thought before I had done
 Of a mocking tale or a gibe
 To please a companion
 Around the fire at the club,
 Being certain that they and I
 But lived where motley is worn:
 All changed, changed utterly:
 A terrible beauty is born.
 That woman's days were spent
 In ignorant good will,
 Her nights in argument
 Until her voice grew shrill.
 What voice more sweet than hers
 When young and beautiful,
 She rode to harriers?
 This man had kept a school
 And rode our winged horse.
 This other his helper and friend
 Was coming into his force;
 He might have won fame in the end,
 So sensitive his nature seemed,
 So daring and sweet his thought.
 This other man I had dreamed
 A drunken, vain-glorious lout.
 He had done most bitter wrong
 o some who are near my heart,
 Yet I number him in the song;
 He, too, has resigned his part
 In the casual comedy;
 He, too, has been changed in his time,
 Transformed utterly:
 A terrible beauty is born.
 '''