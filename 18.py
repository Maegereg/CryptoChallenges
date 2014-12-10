import convert
from aes import *

if __name__ == "__main__":
	ciphertext = convert.b64ToByteString("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")

	key = "YELLOW SUBMARINE"
	nonce = 0

	print aesCTRDecrypt(ciphertext, key, nonce)
	print aesCTRDecrypt(aesCTREncrypt("This was a triumph/I'm making a note here: huge success/It's hard to overstate my satisfaction", "SIXTEEN BYTE KEY", 56) , "SIXTEEN BYTE KEY", 56)