from hardecboracle import *

if __name__ == "__main__":
	if ecboracle.determineIfOracleECB(encryptionBlackBox):
		print repr(breakECBOracle(encryptionBlackBox))