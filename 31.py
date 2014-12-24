import convert
import mac
import string
from time import time
import urllib

def timeSignatureGuess(fileName, signature, address, port):
	paramString = urllib.urlencode({"signature": signature, "file": fileName})
	start = time()
	response = urllib.urlopen(address+":"+str(port)+"/?"+paramString)
	end = time()
	elapsed = end-start
	if response.getcode() == 200:
		return float('inf')
	return elapsed


def guessSignature(filename, address, port):
	signatureGuess = ""
	while timeSignatureGuess(filename, convert.byteStringToHex(signatureGuess), address, port) < float('inf'):
		maxTime = 0
		maxDigit = -1
		for nextByte in range(256):
			guessTime = timeSignatureGuess(filename, convert.byteStringToHex(signatureGuess)+string.rjust(hex(nextByte)[2:], 2, '0'), address, port)
			if guessTime > maxTime:
				maxTime = guessTime
				maxDigit = nextByte
		signatureGuess += chr(maxDigit)
	return convert.byteStringToHex(signatureGuess)



if __name__ == "__main__":
	print guessSignature("foo", "http://localhost", 8080)