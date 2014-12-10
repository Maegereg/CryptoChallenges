from rng import *

if __name__ == "__main__":
	test = MT19937()
	test.setSeed(1)
	print test.next()