import math
import time
from rng import *

#Gets the number of bits needed to represent an integer
def bitLength(integer):
	return int( math.ceil( math.log(integer, 2) ) )

#For y = x^x>>z, given y (result) and z (shiftamount), returns x
def invertRightShiftXor(result, shiftAmount):
	toReturn = result
	numBits = bitLength(result)
	for bitNum in range(numBits)[::-1]:
		toReturn = toReturn^((toReturn&(2**bitNum)) >>shiftAmount )
	assert result == toReturn^(toReturn>>shiftAmount)
	return toReturn

#For y = x^((x<<z) & n), given y (result), z (shiftAmount), and n (andNumber), returns x
def invertLeftShiftAnd(result, shiftAmount, andNumber):
	toReturn = result
	numBits = max(bitLength(result), bitLength(andNumber))
	for bitNum in range(shiftAmount, numBits):
		if (andNumber & 2**bitNum):
			toReturn = toReturn^((toReturn<<shiftAmount) & 2**bitNum )
	assert result == toReturn^((toReturn<<shiftAmount) & andNumber)
	return toReturn

#Inverse of the tempering function of the MT19937 RNG
def untemper(rngOutput):
	toReturn = invertRightShiftXor(rngOutput, 18)
	toReturn = invertLeftShiftAnd(toReturn, 15, 4022730752)
	toReturn = invertLeftShiftAnd(toReturn, 7, 2636928640)
	return invertRightShiftXor(toReturn, 11)

#Returns an MT19937 object that should have identical internal state to the provided one
def duplicateMT19937(toDuplicate):
	internalState = []
	for i in range(624):
		internalState.append(untemper(toDuplicate.next()))
	toReturn = MT19937()
	toReturn.state = internalState
	return toReturn




if __name__ == "__main__":
	#Test invertRightShiftXor
	x = 8291379723891
	y = x^(x>>8)
	assert invertRightShiftXor(y, 8) == x

	#Test invertLeftShiftAnd
	n = 9328749823
	y = x^((x<<9) & n)
	assert invertLeftShiftAnd(y, 9, n) == x

	testGenerator = MT19937()
	testGenerator.setSeed(int(time.time()))
	duplicate = duplicateMT19937(testGenerator)

	for i in range(1000):
		assert testGenerator.next() == duplicate.next()

	print "Duplicated generator successfully"

