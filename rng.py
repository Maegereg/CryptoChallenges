'''
Implements the Mersenne Twister MT19937 PRNG
Based on psuedocode from http://en.wikipedia.org/wiki/Mersenne_twister
'''
class MT19937:
	def __init__(self):
		self.state = [0]*624
		self.index = 0

	def setSeed(self, seed):
		self.index = 0
		self.state[0] = seed
		for i in range(1, len(self.state)):
			self.state[i] = (1812433253*((self.state[i-1]>>30)^self.state[i-1])+i)&(2**32-1)

	def _updateState(self):
		for i in range(len(self.state)):
			y = (self.state[i] & 2147483648) + (self.state[(i+1)%len(self.state)] & 2147483647) #Magic numbers are 2**31 and 2**31-1
			self.state[i] = self.state[(i+391)%len(self.state)] ^ (y>>1)
			if (y%2 != 0):
				self.state[i] = self.state[i] ^ 2567483615

	def next(self):
		if self.index == 0:
			self._updateState()

		y = self.state[self.index]
		y = y^(y>>11)
		y = y^((y<<7) & 2636928640)
		y = y^((y<<15) & 4022730752)
		y = y^(y>>18)

		self.index = (self.index+1)%624
		return y
