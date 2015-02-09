class PaddingError(Exception):
	pass

#Pads a block (string) to the given block length using PKCS#7
#Assumes that we will never be asked to add more than 255 bytes of padding
def pkcs7(block, blocklen):
	numPadding = blocklen - len(block)
	if numPadding <= 0:
		return block
	else:
		return block+chr(numPadding)*numPadding

#Adds the smallest amount of valid padding such that the string is a multiple of the block length
def pkcs7String(string, blocklen):
	if len(string) % blocklen == 0:
		return pkcs7(string, len(string)+blocklen)
	else:
		paddedLen = (len(string)/blocklen + 1)*blocklen
		return pkcs7(string, paddedLen)


#Removes pkcs7 padding from a string. Raises a PaddingError if padding is not valid.
def stripPkcs7(text):
	numBytes = ord(text[-1])
	if text[-numBytes:] != chr(numBytes)*numBytes:
		raise PaddingError("Invalid padding")
	return text[:-numBytes]
