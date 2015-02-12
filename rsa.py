import convert
import hash
import padding
import random
import math

STANDARD_E = 3
STANDARD_MIN = 2**128
STANDARD_MAX = 2**129

#Performs the Miller-Rabin primality test on n, with k iterations. If it returns false, n is composite. If it returns true,
# n has less than a 1/4^k chance of being composite
def millerRabinTest(n, k):
    d = n-1
    s = 0
    prime = False
    while d%2 == 0:
        d = d/2
        s += 1
    for i in range(0, k):
        #Insucure - should use /dev/urandom instead
        a = random.randint(2, n-2)
        temp = pow(a, d, n)
        prime = prime or temp == 1 or temp == n-1
        for r in range(1, s):
            temp = pow(a, (2**r)*d, n)
            prime = prime or temp == n-1
        if not prime:
            return False
    return True
        
#Performs the euclidian extended gcd algorithm
def extended_gcd(a, b):
    x = 0
    y = 1
    lastx = 1
    lasty = 0
    while not b == 0:
        q = a/b
        a, b = b, a%b
        x, lastx = lastx-q*x, x
        y, lasty = lasty-q*y, y
    return lastx, lasty, a

def modInverse(a, m):
    x, y, g = extended_gcd(a, m)
    return x%m

'''
Generates a public/private key pair with min <= n <= max
Returns ((e, n), (d, n)) where (e, n) is the public key and (d, n) is the private key
'''
def keygen(min=STANDARD_MIN, max=STANDARD_MAX, e=STANDARD_E):
    primes = []
    while len(primes) < 2:
        possible = random.randint(int(math.sqrt(min)), int(math.sqrt(max)))
        if millerRabinTest(possible, 100) and not possible in primes and not possible%e == 1:
            primes.append(possible)
    n = (primes[0])*(primes[1])
    totient = (primes[0]-1)*(primes[1]-1)
    d = modInverse(e, totient)
    return ((e, n), (d, n))

'''
Accepts a message, and a public key in the form (e, n)
Only works if message < n
'''
def encryptInt(message, pubKey):
    return pow(message, pubKey[0], pubKey[1])

'''
Accepts a message, and a public key in the form (d, n)
Identical to encryption
'''
def decryptInt(ciphertext, privateKey):
    return encryptInt(ciphertext, privateKey)

'''
Transforms a plaintext message into a list of integers 
NOTE: while decodePlaintext(encodePlaintext(input)) is garuanteed to produce input,
encodePlaintext(decodePlaintext(input)) is not garuanteed to produce input
key can be either a public or private key in the form of (e/d, n)
'''
def encodePlaintext(message, key, pad=True):
    #The largest number of bytes that can only represent numbers smaller than the modulus.
    blockLen = blockLen = int(math.log(key[1], 256))
    if pad:
        paddedMessage = padding.pkcs7String(message, blockLen)
    else:
        paddedMessage = message

    numblocks = int(math.ceil(len(paddedMessage)/float(blockLen)))
    chunkedMessage = [paddedMessage[i*blockLen: (i+1)*blockLen] for i in range( numblocks )]
    return map(convert.byteStringToInt, chunkedMessage)

'''
Performs the reverse operation of encodePlaintext
NOTE: while decodePlaintext(encodePlaintext(input)) is garuanteed to produce input,
encodePlaintext(decodePlaintext(input)) is not garuanteed to produce input
NOTE: if the original message was not a multiple of the blockLen and padding is off, this
process will not reproduce the orginal message
key can be either a public or private key in the form of (e/d, n)
'''
def decodePlaintext(encodedMessage, key, pad = True):
    blockLen = blockLen = int(math.log(key[1], 256))
    chunkedMessage = map(lambda x: convert.intToByteString(x).rjust(blockLen, chr(0)), encodedMessage)
    if pad:
        return padding.stripPkcs7("".join(chunkedMessage))
    else:
        return "".join(chunkedMessage)

'''
Takes the simple ciphertext form (a list of integers) and decodes to it a string
NOTE: while encodedCiphertext(decodeCiphertext(input)) is garuanteed to produce input,
key can be either a public or private key in the form of (e/d, n)
'''
def decodeCiphertext(encodedCiphertext, key):
    #Encrypted messages have a blockLength one greater than plaintext
    #We want the smallest number of bytes that can represent the modulus, which is at most one greater than plaintext blocklength
    #(Technically that number could be blockLen, but absolute smallest isn't important)
    chunkLen = int(math.log(key[1], 256))+1
    return "".join(map(lambda x: convert.intToByteString(x).rjust(chunkLen, chr(0)), encodedCiphertext))

'''
Performs the reverse operation of decodeCiphertext. 
Takes a string and returns a list of integers
key can be either a public or private key in the form of (e/d, n)
'''
def encodeCiphertext(ciphertext, key):
    chunkLen = int(math.log(key[1], 256))+1
    encryptedChunks = [ciphertext[i* chunkLen: (i+1)*chunkLen] for i in range(len(ciphertext)/ chunkLen)]
    return map(convert.byteStringToInt, encryptedChunks)

'''
Encrypts an arbitrary length string
Public key must be in the form (e, n)
Returns a string
'''
def encryptString(message, pubKey, ignorePadding=False):
    encodedMessage = encodePlaintext(message, pubKey, not ignorePadding)
    encryptedChunks = map(lambda x: encryptInt(x, pubKey), encodedMessage)
    return decodeCiphertext(encryptedChunks, pubKey)

'''
Private key must be in the form (d, n)
Returns a string
'''
def decryptString(ciphertext, privateKey, ignorePadding=False):    
    chunkLen = int(math.log(privateKey[1], 256))+1
    encryptedChunks = encodeCiphertext(ciphertext, privateKey)
    chunkedMessage = map(lambda x: decryptInt(x, privateKey), encryptedChunks)
    return decodePlaintext(chunkedMessage, privateKey, not ignorePadding)

'''
Uses a similar but not identical format to PKCS1
This signature omits the ASN.1 identifier
message should be a string
blockLen should be an integer
hashFunction should be a hash function that accepts a string and returns an integer
Returns a string
'''
def generateSignatureBlock(message, blockLen=128, hashFunction=hash.sha256):
    digest = convert.intToByteString(hashFunction(message))
    signatureBlock = chr(0)+digest
    signatureBlock = signatureBlock.rjust(blockLen-len(signatureBlock)-2, chr(255))
    return chr(0)+chr(1)+signatureBlock

'''
Generates a signature for the given message based on the given private key
Returns a string
'''
def generateSignature(message, privateKey):
    signatureBlock = generateSignatureBlock(message)
    return decryptString(signatureBlock, privateKey, True)

'''
Checks whether the given signature was generated by the owner of the public key for the given message
Returns a boolean
'''
def checkSignature(message, signature, publicKey):
    signatureBlock = generateSignatureBlock(message)
    print repr(signatureBlock)
    decryptedSignature = encryptString(signature, publicKey, True)
    return signatureBlock == decryptedSignature

'''
Similar to checkSignature, but doesn't completely verify the format of the signature block
'''
def flawedCheckSignature(message, signature, publicKey):
    decryptedSignature = encryptString(signature, publicKey, True)
    messageDigest = convert.intToByteString(hash.sha256(message))
    return (decryptedSignature[-1:-1*len(messageDigest)] == messageDigest and
        decryptedSignature[-1*len(messageDigest)] == chr(0) and
        decryptedSignature[0:3] == chr(0)+chr(1)+chr(255))


if __name__ == "__main__":
    testMessage = "This"

    pubKey, privKey = keygen()

    ciphertext = encryptString(testMessage, pubKey)

    plaintext = decryptString(ciphertext, privKey)

    assert plaintext == testMessage
    '''
    plaintext = '\x01"s\xf4$`\xae\xde\x00\xb0\xeb7\xf1\x00aAR'
    e = 3
    n = 536161364582062137235869697073367946849L
    assert encodePlaintext(plaintext, (e, n), False) == [convert.byteStringToInt(plaintext)]
    '''
    signature = generateSignature(testMessage, privKey)
    assert checkSignature(testMessage, signature, pubKey)
    _, newPrivKey = keygen()
    badSignature = generateSignature(testMessage, newPrivKey)
    assert not checkSignature(testMessage, badSignature, pubKey)


