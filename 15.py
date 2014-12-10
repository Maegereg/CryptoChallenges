from padding import *

if __name__ == "__main__":
	print repr(pkcs7("YELLOW SUBMARINE", 20))

	#EX 15
	print repr(stripPkcs7( pkcs7("Yellow Submarine", 20)))
	print repr(stripPkcs7( "stuff"+chr(3)+chr(3)))