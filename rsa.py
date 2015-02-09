import convert
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
Encrypts an arbitrary length string
Public key must be in the form (e, n)
Returns a string
'''
def encryptString(message, pubKey):
    #The largest number of bytes that can only represent numbers smaller than the modulus.
    blockLen = int(math.log(pubKey[1], 256))
    paddedMessage = padding.pkcs7String(message, blockLen)
    chunkedMessage = [paddedMessage[i* blockLen: (i+1)*blockLen] for i in range(len(paddedMessage)/ blockLen)]
    encryptedChunks = map(lambda x: encryptInt(convert.byteStringToInt(x), pubKey), chunkedMessage)
    #Encrypted messages have a blockLength one greater than plaintext
    #We want the smallest number of bytes that can represent the modulus, which is at most one greater than plaintext blocklength
    #(Technically that number could be blockLen, but absolute smallest isn't important)
    return "".join(map(lambda x: convert.intToByteString(x).rjust(blockLen+1, chr(0)), encryptedChunks))

'''
Private key must be in the form (d, n)
Returns a string
'''
def decryptString(ciphertext, privateKey):    
    chunkLen = int(math.log(privateKey[1], 256))+1
    encryptedChunks = [ciphertext[i* chunkLen: (i+1)*chunkLen] for i in range(len(ciphertext)/ chunkLen)]
    encryptedChunks = map(convert.byteStringToInt, encryptedChunks)
    chunkedMessage = map(lambda x: convert.intToByteString(decryptInt(x, privateKey)).rjust(chunkLen-1, chr(0)), encryptedChunks)
    return padding.stripPkcs7("".join(chunkedMessage))

if __name__ == "__main__":
    testMessage = "This is a test message of unusual length that will have to be broken into segments"

    pubKey, privKey = keygen()

    ciphertext = encryptString(testMessage, pubKey)

    plaintext = decryptString(ciphertext, privKey)

    assert plaintext == testMessage
