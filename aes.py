from Crypto.Cipher import AES
import convert
import math
import random
import string
from xor import *
from padding import *


#block size in bytes
AES_BLOCK_SIZE = 16

def aesEncrypt(block, key):
	cipher = AES.new(key, AES.MODE_ECB)
	return cipher.encrypt(block)

def aesDecrypt(block, key):
	cipher = AES.new(key, AES.MODE_ECB)
	return cipher.decrypt(block)

#Random 128 bit (16 byte) string
def generateRandomKey():
	return "".join([chr(random.randint(0, 255)) for i in range(16)])

#Uses PKCS#7
#Always adds padding
def padForAES(plaintext):
	if len(plaintext) % AES_BLOCK_SIZE == 0:
		return pkcs7(plaintext, len(plaintext)+AES_BLOCK_SIZE)
	else:
		return pkcs7(plaintext, ((len(plaintext)/16)+1)*16)

#Uses PKCS#7
#Assumes input is padded using PKCS. Always removes something.
def removePadding(plaintext):
	return plaintext[:len(plaintext)-ord(plaintext[-1])]

def aesECBEncrypt(plaintext, key):
	paddedText = padForAES(plaintext)
	return aesEncrypt(paddedText, key)

def aesECBDecrypt(ciphertext, key):
	paddedPlaintext = aesDecrypt(ciphertext, key)
	return removePadding(paddedPlaintext)

def aesCBCEncrypt(plaintext, key, IV):
	paddedText = padForAES(plaintext)
	cipherblocks = [IV]
	startBlock = 0
	while startBlock < len(paddedText):
		cipherblocks.append( aesEncrypt( xorByteStrings(paddedText[startBlock:startBlock+AES_BLOCK_SIZE], cipherblocks[-1] ), key ))
		startBlock += AES_BLOCK_SIZE
	return "".join(cipherblocks[1:])

#Throws an exception if the padding is incorrect
def aesCBCDecrypt(ciphertext, key, IV):
	plaintext = ""
	startBlock = 0
	lastCipherBlock = IV
	while startBlock < len(ciphertext):
		curBlock = ciphertext[startBlock:startBlock+AES_BLOCK_SIZE]
		plaintext += xorByteStrings( aesDecrypt(curBlock, key), lastCipherBlock)
		lastCipherBlock = curBlock
		startBlock += AES_BLOCK_SIZE
	return stripPkcs7(plaintext)

#Generates length bytes of keystream based on AES in CTR mode
#64-bit nonce, 64-bit counter, both little endian, concatenated in that order
def generateCTRKeystream(length, key, nonce):
	nonce = nonce%(2**64)
	counter = 0
	keystream = ""
	while len(keystream) < length:
		#Concatenate the nonce and the counter
		inputBlock = string.ljust(convert.intToByteString(nonce, bigEndian=False), 8, chr(0))+string.ljust(convert.intToByteString(counter, bigEndian=False), 8, chr(0))
		keystream = keystream+aesEncrypt(inputBlock, key)
		counter += 1
		counter = counter%(2**64)
	return keystream[:length]

#Encrypts the plaintext based on AES in CTR mode
def aesCTREncrypt(plaintext, key, nonce):
	return xorByteStrings(generateCTRKeystream(len(plaintext), key, nonce), plaintext)
	
#Decrypts the plaintext based on AES in CTR mode
#Encryption and decryption are the same operation
def aesCTRDecrypt(ciphertext, key, nonce):
	return aesCTREncrypt(ciphertext, key, nonce)

def editCTR(ciphertext, key, nonce, offset, newtext):
	plaintext = aesCTRDecrypt(ciphertext, key, nonce)
	newplaintext = plaintext[:offset]+newtext+plaintext[offset+len(newtext):]
	return aesCTREncrypt(newplaintext, key, nonce)