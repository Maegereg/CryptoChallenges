import convert
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
Returns (e, d, n) where (e, n) is the public key and (d, n) is the private key
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
    return (e, d, n)

#Only works if message < n
def encryptInt(message, e, n):
    return pow(message, e, n)

#Decryption is identical to encryption
def decryptInt(ciphertext, d, n):
    return encryptInt(ciphertext, d, n)

'''
Encrypting strings is a bit more difficult: 
we have to make sure that the integer representation isn't bigger than n
'''
def encryptString(message, e, n):
    maximumLength = int(math.log(n, 256))
    choppedMessage = [message[i* maximumLength: (i+1)*maximumLength] for i in range(len(message)/ maximumLength+1)]
    return map(lambda x: encryptInt(convert.byteStringToInt(x), e, n), choppedMessage)

def decryptString(ciphertext, d, n):
    return "".join(map(lambda x: convert.intToByteString(decryptInt(x, d, n)), ciphertext))

if __name__ == "__main__":
    testMessage = "This is a test message of unusual length that will have to be broken into segments"

    e, d, n = keygen()

    ciphertext = encryptString(testMessage, e, n)

    plaintext = decryptString(ciphertext, d, n)

    assert plaintext == testMessage
