import random
import time
from rng import *

def getDelayedRandint():
	time.sleep(random.randint(40, 1000))
	generator = MT19937()
	generator.setSeed(int(time.time()))
	result = generator.next()
	time.sleep(random.randint(40, 1000))
	return result


def findSeed(delayFunction):
	startTime = int(time.time())
	firstResult = delayFunction()
	endTime = int(time.time())
	generator = MT19937()
	for i in range(startTime, endTime):
		generator.setSeed(i)
		if generator.next() == firstResult:
			return i


if __name__ == "__main__":
	print findSeed(getDelayedRandint)