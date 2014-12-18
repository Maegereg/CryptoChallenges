import math
import struct

#Performs a left rotation (unlike a left shift, the high order bits are moved to the lower order places when they overflow bitlen)
def leftRotate(input, places, bitlen):
	truePlaces = places%bitlen
	return ((input<<truePlaces)+(input>>(bitlen-truePlaces)))&(2**bitlen-1)

#Implemented myself, because why not?
#Based on psuedocode from http://en.wikipedia.org/wiki/SHA-1
#Also looked at code at https://github.com/ajalt/python-sha1/blob/master/sha1.py
def sha1(message):
	h0 = 0x67452301
	h1 = 0xEFCDAB89
	h2 = 0x98BADCFE
	h3 = 0x10325476
	h4 = 0xC3D2E1F0

	paddedMessage = message+chr(0x80)
	paddedMessage = paddedMessage+(chr(0)*(56 - len(paddedMessage)%64 if len(paddedMessage)%64 <= 56 else 56+ 64 - len(paddedMessage)%64 ))
	paddedMessage = paddedMessage+struct.pack(">Q", len(message)*8)	


	for i in range(0, len(paddedMessage), 64):
		curChunk = paddedMessage[i:i+64]
		w = [struct.unpack(">I", curChunk[i:i+4])[0] for i in range(0, len(curChunk), 4)]
		for i in range(len(w), 80):
			w.append(leftRotate(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1, 32))


		a = h0
		b = h1
		c = h2
		d = h3
		e = h4

		for i in range(80):
			if i < 20:
				f = (b & c) | ((~b) & d)
				k = 0x5A827999
			elif i < 40:
				f = b ^ c ^ d
				k = 0x6ED9EBA1
			elif i < 60:
				f = (b & c) | (b & d) | (c & d)
				k = 0x8F1BBCDC
			else:
				f = b ^ c ^ d
				k = 0xCA62C1D6

			temp = (leftRotate(a, 5, 32) + f + e + k + w[i]) & (2**32-1)
			e = d
			d = c
			c = leftRotate(b, 30, 32)
			b = a
			a = temp

		h0 = (h0+a) & (2**32-1)
		h1 = (h1+b) & (2**32-1)
		h2 = (h2+c) & (2**32-1)
		h3 = (h3+d) & (2**32-1)
		h4 = (h4+e) & (2**32-1)

		#print h0,h1,h2,h3,h4

	return h0<<128 | h1<<96 | h2<<64 | h3<<32 | h4

def testSha1():
	print "Checking SHA1 output against known values:"
	try:
		assert sha1("The quick brown fox jumps over the lazy dog") == 0x2fd4e1c67a2d28fced849ee1bb76e7391b93eb12
		print ".",
		assert sha1("The quick brown fox jumps over the lazy cog") == 0xde9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3
		print ".",
		assert sha1("") == 0xda39a3ee5e6b4b0d3255bfef95601890afd80709
		print ".",
	except AssertionError:
		print "Failed. SHA-1 implementation broken."
		return
	print "Passed all tests"


if __name__ == "__main__":
    testSha1()
