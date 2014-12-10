class PaddingError(Exception):
	pass

#Pads a block (string) to the given block length using PKCS#7
def pkcs7(block, blocklen):
	numPadding = blocklen - len(block)
	if numPadding <= 0:
		return block
	else:
		return block+chr(numPadding)*numPadding

#Removes pkcs7 padding from a string. Raises a PaddingError if padding is not valid.
def stripPkcs7(text):
	numBytes = ord(text[-1])
	if text[-numBytes:] != chr(numBytes)*numBytes:
		raise PaddingError("Invalid padding")
	return text[:-numBytes]
