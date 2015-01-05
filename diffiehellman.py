import random

STANDARD_P = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
STANDARD_G = 2


def generatePrivateKey(p = STANDARD_P):
	return random.randint(0, p)

def generatePublicValue(privateKey, g = STANDARD_G, p = STANDARD_P):
	return pow(g, privateKey, p)

def deriveSecret(publicValue, privateKey, p = STANDARD_P):
	return pow(publicValue, privateKey, p)

if __name__ == "__main__":
	a = generatePrivateKey()
	b = generatePrivateKey()

	A = generatePublicValue(a)
	B = generatePublicValue(b)

	assert deriveSecret(A, b) == deriveSecret(B, a)