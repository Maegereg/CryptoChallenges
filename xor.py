import convert

def xorByteStrings(bString1, bString2):
	output = ""
	for i in range(len(bString2)):
		output = output+ chr(ord(bString2[i]) ^ ord(bString1[i]))
	return output

def xorHexStrings(hexString1, hexString2):
	return convert.byteStringToHex(xorByteStrings(convert.hexToByteString(hexString1), convert.hexToByteString(hexString2)))