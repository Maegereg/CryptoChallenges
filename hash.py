import math
import struct

#Performs a left rotation (unlike a left shift, the high order bits are moved to the lower order places when they overflow bitlen)
def leftRotate(input, places, bitlen):
	truePlaces = places%bitlen
	return ((input<<truePlaces)+(input>>(bitlen-truePlaces)))&(2**bitlen-1)

#Performs padding according to SHA-1 specifications
def mdPad(message, bigEndian = True):
	paddedMessage = message+chr(0x80)
	paddedMessage = paddedMessage+(chr(0)*(56 - len(paddedMessage)%64 if len(paddedMessage)%64 <= 56 else 56+ 64 - len(paddedMessage)%64 ))
	paddedMessage = paddedMessage+(struct.pack(">Q", len(message)*8) if bigEndian else struct.pack("<Q", len(message)*8))
	return paddedMessage

'''Implemented myself, because why not?
Based on psuedocode from http://en.wikipedia.org/wiki/SHA-1
Also looked at code at https://github.com/ajalt/python-sha1/blob/master/sha1.py
Optional parameters allow length extensions. r0, r1, etc allow setting the hash 
registers to a different initial value (like the end values of a different hash)
extraLength allows manipulation of the length padding for extension (measured in bytes)
'''
def sha1(message, r0 = 0x67452301, r1 = 0xEFCDAB89, r2 = 0x98BADCFE,
		 r3 = 0x10325476, r4 = 0xC3D2E1F0, extraLength = 0):
	h0 = r0
	h1 = r1
	h2 = r2
	h3 = r3
	h4 = r4

	paddedMessage = mdPad((chr(0)*extraLength)+message)[extraLength:]


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

def md4RoundFunction(r1, r2, r3, r4, func, constant, word, rotate):
	return leftRotate((r1 + func(r2, r3, r4) + word + constant)&(2**32-1), rotate, 32)

def md4Round1Func(r1, r2, r3, r4, word, rotate):
	return md4RoundFunction(r1, r2, r3, r4, lambda x, y, z: (x&y) | ((~x) & z), 0, word, rotate)

def md4Round2Func(r1, r2, r3, r4, word, rotate):
	return md4RoundFunction(r1, r2, r3, r4, lambda x, y, z: (x&y) | (x & z) | (y&z), 0x5A827999, word, rotate)

def md4Round3Func(r1, r2, r3, r4, word, rotate):
	return md4RoundFunction(r1, r2, r3, r4, lambda x, y, z: x^y^z, 0x6ED9EBA1, word, rotate)

def reverseBytes(toReverse):
	output = 0
	while toReverse > 0:
		output = output<<8
		output += toReverse & 255
		toReverse = toReverse>>8
	return output

'''
Also implemented myself, for similar reasons
This implementation based on RFC 1320
Debugged with the help of https://gist.github.com/tristanwietsma/5937448
'''
def md4(message):
	a = 0x67452301
	b = 0xEFCDAB89
	c = 0x98BADCFE
	d = 0x10325476

	paddedMessage = mdPad(message, bigEndian=False)

	for i in range(0, len(paddedMessage), 64):
		curChunk = paddedMessage[i:i+64]
		X = [struct.unpack("<I", curChunk[i:i+4])[0] for i in range(0, len(curChunk), 4)]


		AA = a
		BB = b
		CC = c
		DD = d

		#Round 1, in which we wonder why this isn't a loop
		a = md4Round1Func(a,b,c,d,X[0],3)
		d = md4Round1Func(d,a,b,c,X[1],7)
		c = md4Round1Func(c,d,a,b,X[2],11)
		b = md4Round1Func(b,c,d,a,X[3],19)
		a = md4Round1Func(a,b,c,d,X[4],3)
		d = md4Round1Func(d,a,b,c,X[5],7)
		c = md4Round1Func(c,d,a,b,X[6],11)
		b = md4Round1Func(b,c,d,a,X[7],19)
		a = md4Round1Func(a,b,c,d,X[8],3)
		d = md4Round1Func(d,a,b,c,X[9],7)
		c = md4Round1Func(c,d,a,b,X[10],11)
		b = md4Round1Func(b,c,d,a,X[11],19)
		a = md4Round1Func(a,b,c,d,X[12],3)
		d = md4Round1Func(d,a,b,c,X[13],7)
		c = md4Round1Func(c,d,a,b,X[14],11)
		b = md4Round1Func(b,c,d,a,X[15],19)

		#Round 2, in which we realize why it isn't a loop and groan is dispair
		a = md4Round2Func(a,b,c,d,X[0],3)
		d = md4Round2Func(d,a,b,c,X[4],5)
		c = md4Round2Func(c,d,a,b,X[8],9)
		b = md4Round2Func(b,c,d,a,X[12],13)
		a = md4Round2Func(a,b,c,d,X[1],3)
		d = md4Round2Func(d,a,b,c,X[5],5)
		c = md4Round2Func(c,d,a,b,X[9],9)
		b = md4Round2Func(b,c,d,a,X[13],13)
		a = md4Round2Func(a,b,c,d,X[2],3)
		d = md4Round2Func(d,a,b,c,X[6],5)
		c = md4Round2Func(c,d,a,b,X[10],9)
		b = md4Round2Func(b,c,d,a,X[14],13)
		a = md4Round2Func(a,b,c,d,X[3],3)
		d = md4Round2Func(d,a,b,c,X[7],5)
		c = md4Round2Func(c,d,a,b,X[11],9)
		b = md4Round2Func(b,c,d,a,X[15],13)


		#Round 3, in which we grow tired of this nonsense
		a = md4Round3Func(a,b,c,d,X[0],3)
		d = md4Round3Func(d,a,b,c,X[8],9)
		c = md4Round3Func(c,d,a,b,X[4],11)
		b = md4Round3Func(b,c,d,a,X[12],15)
		a = md4Round3Func(a,b,c,d,X[2],3)
		d = md4Round3Func(d,a,b,c,X[10],9)
		c = md4Round3Func(c,d,a,b,X[6],11)
		b = md4Round3Func(b,c,d,a,X[14],15)
		a = md4Round3Func(a,b,c,d,X[1],3)
		d = md4Round3Func(d,a,b,c,X[9],9)
		c = md4Round3Func(c,d,a,b,X[5],11)
		b = md4Round3Func(b,c,d,a,X[13],15)
		a = md4Round3Func(a,b,c,d,X[3],3)
		d = md4Round3Func(d,a,b,c,X[11],9)
		c = md4Round3Func(c,d,a,b,X[7],11)
		b = md4Round3Func(b,c,d,a,X[15],15)

		a = (a+AA)&(2**32-1)
		b = (b+BB)&(2**32-1)
		c = (c+CC)&(2**32-1)
		d = (d+DD)&(2**32-1)

	return reverseBytes(a)<< 96 | reverseBytes(b) << 64 | reverseBytes(c) << 32 | reverseBytes(d)


def testMD4():
	print "Checking MD4 output against known values:"
	try:
		assert md4("The quick brown fox jumps over the lazy dog") == 0x1bee69a46ba811185c194762abaeae90
		print ".",
		assert md4("The quick brown fox jumps over the lazy cog") == 0xb86e130ce7028da59e672d56ad0113df
		print ".",
		assert md4("") == 0x31d6cfe0d16ae931b73c59d7e0c089c0
		print ".",
	except AssertionError:
		print "Failed. MD4 implementation broken."
		return
	print "Passed all tests"


if __name__ == "__main__":
    testSha1()
    testMD4()