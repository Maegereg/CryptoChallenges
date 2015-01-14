import convert
import diffiehellman as dh
import hash
import mac
import random
import sys

STANDARD_G = 2
STANDARD_K = 3
STANDARD_N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff

#Returns a string
def generateRandomSalt():
	return convert.intToByteString(random.randint(0, sys.maxint))

#Returns an integer
def generatePrivateKey(N = STANDARD_N):
	return dh.generatePrivateKey(N)

def getHashInt(value):
	return hash.sha256(value)

'''
Generates the password verifier stored by the server. password and salt should be strings.
Returns an integer
'''
def generatePasswordVerifier(password, salt, g = STANDARD_G, N = STANDARD_N):
	hashedPasswordInt = getHashInt(password+salt)
	return pow(g, hashedPasswordInt, N)

'''
Generates the value the client sends to the server, based on its private key. 
Private key should be an integer.
Returns an integer
'''
def generateClientPublicValue(privateKey, g = STANDARD_G, N = STANDARD_N):
	return pow(g, privateKey, N)

'''
Generates the value the server sends to the client, based on its private key and the password verifier. Password verfifier and private key should be ints.
Returns an integer
'''
def generateServerPublicValue(privateKey, passwordVerifier, g = STANDARD_G, k = STANDARD_K, N = STANDARD_N):
	return (pow(g, privateKey, N)+(k*passwordVerifier))%N

'''
Takes the two public values and produces a hash of their concatenation used to derive the shared secret.
Both public values should be integers, produces an integer
'''
def derivePublicValueHash(publicValueA, publicValueB):
	return hash.sha256(convert.intToByteString(publicValueA) + convert.intToByteString(publicValueB))

'''
Derives the shared secret based on the values available to the client.
Password and salt should be strings
clientPrivateKey and serverPublicValue should be integers
Returns a string
'''
def clientDeriveSharedSecret(password, salt, clientPrivateKey, serverPublicValue, g = STANDARD_G, k = STANDARD_K, N = STANDARD_N):
	x = getHashInt(password+salt)
	publicValueHash = derivePublicValueHash(generateClientPublicValue(clientPrivateKey, g, N), serverPublicValue)
	S = pow((serverPublicValue - k*pow(g, x, N)), (clientPrivateKey+publicValueHash*x), N)
	return convert.intToByteString(hash.sha256(convert.intToByteString(S)))

'''
Derives the shared secret based on the values available to the server.
clientPublicValue, serverPrivateKey and passwordVerfifier should be integers
Returns a string
'''
def serverDeriveSharedSecret(clientPublicValue, serverPrivateKey, passwordVerifier, g= STANDARD_G, k = STANDARD_K, N = STANDARD_N):
	publicValueHash = derivePublicValueHash(clientPublicValue, generateServerPublicValue(serverPrivateKey, passwordVerifier, g, k, N))
	S = pow(clientPublicValue*pow(passwordVerifier, publicValueHash, N), serverPrivateKey, N)
	return convert.intToByteString(hash.sha256(convert.intToByteString(S)))

'''
Based on the shared secret and the salt, generates a public value the client can transmit to
the server to ensure that they have the same shared secret
sharedSecret and salt should be strings
Returns an integer
'''
def generateClientValidator(sharedSecret, salt):
	return mac.HMAC_SHA256(sharedSecret, salt)

if __name__ == "__main__":
	password = "thisisaverystrongpasswor"

	salt = generateRandomSalt()

	a = generatePrivateKey()
	b = generatePrivateKey()

	v = generatePasswordVerifier(password, salt)

	A = generateClientPublicValue(a)
	B = generateServerPublicValue(b, v)

	u = derivePublicValueHash(A, B)

	Ka = clientDeriveSharedSecret(password, salt, a, B)
	Kb = serverDeriveSharedSecret(A, b, v)

	assert generateClientValidator(Ka, salt) == generateClientValidator(Kb, salt)
	print "SRP works"
