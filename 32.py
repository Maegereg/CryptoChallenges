import convert
import mac
import random
import string
from time import time
import urllib

realTimes = []

'''For testing purposes. Obtains 1000 samples of real latency, and then replays them,
   inserting additional delay for comparison as appropriate. Also only works for fileName foo'''
def simulateTimeSignatureGuess(fileName, signature, address, port):
	actualSignature = 'b95e9bce3829ac97c6d813861b06841983bff6c1'
	if signature == actualSignature:
		return float('inf')
	global realTimes
	if len(realTimes) < 1000:
		latency = timeSignatureGuess("foo", chr(0), address, port)
		realTimes.append(latency)
	else:
		latency = random.sample(realTimes, 1)[0]
	sameCharacters = 0
	while sameCharacters < min(len(signature), len(actualSignature)) and actualSignature[sameCharacters] == signature[sameCharacters]:
		sameCharacters += 1
	return latency+(.005*sameCharacters)

'''Returns the length of time it took to submit and recieve the response for guessing 
the particular fileName and signature. Returns float('inf') if the signature is correct.
'''
def timeSignatureGuess(fileName, signature, address, port):
	paramString = urllib.urlencode({"signature": signature, "file": fileName})
	start = time()
	response = urllib.urlopen(address+":"+str(port)+"/?"+paramString)
	end = time()
	elapsed = end-start
	if response.getcode() == 200:
		return float('inf')
	return elapsed


'''Performs the attack to get the appropriate signature for the filename
'''
def guessSignature(filename, address, port):
	signatureGuess = ""
	#For each possible byte, a list of all the times for that byte
	guessTimes = []
	for i in range(255):
		guessTimes.append([])
	#The number of guess attempts taken for each digit
	numAttempts = 0

	maxTime = 0
	maxByte = 0
	while timeSignatureGuess(filename, convert.byteStringToHex(signatureGuess), address, port) < float('inf'):
		for byteGuess in range(255):
			guessTime =timeSignatureGuess(filename, convert.byteStringToHex(signatureGuess)+string.rjust(hex(byteGuess)[2:], 2, '0'), address, port)
			guessTimes[byteGuess].append(guessTime)
			#Sum is an equivalent measure to average
			currentAvg = sum(guessTimes[byteGuess])
			if currentAvg > maxTime:
				maxTime = currentAvg
				maxByte = byteGuess

		numAttempts += 1

		#Find the second highest average time
		secondTime = max(filter(lambda x: x != maxTime, map(sum, guessTimes)))
		#The % of the difference between the maximum and second place sum times
		percentAhead = (maxTime-secondTime)/secondTime

		if ((numAttempts >= 100)):
			signatureGuess += chr(maxByte)
			#Progress indicator
			print ".",
			#re-initialize
			guessTimes = []
			for i in range(255):
				guessTimes.append([])
			numAttempts = 0
		maxTime = 0
		maxByte = 0
	return convert.byteStringToHex(signatureGuess)



if __name__ == "__main__":
	print guessSignature("foo", "http://localhost", 8080)