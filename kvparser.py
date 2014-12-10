import aes
import ecboracle

#Object represents a set of key/value pairings, and maintains their order
#Indexing and iterators work with the same behavior as for a dictionary
class KVObject:
	def __init__(self, serializedVersion = ""):
		self.attributes = []
		if serializedVersion != "":
			for pair in serializedVersion.split("&"):
				splitPair = pair.split('=')
				self.addKV(splitPair[0], splitPair[1])

	def addKV(self, key, value):
		self.attributes.append((key, value))

	def __getitem__(self, key):
		for pair in self.attributes:
			if pair[0] == key:
				return pair[1]

	def __iter__(self):
		return map(lambda x: x[0], self.attributes).__iter__()

	def serialize(self):
		return "&".join(map(lambda x: str(x[0])+"="+str(x[1]), self.attributes))

#Encodes a profile for the given email in =& notation with the provided email, the role user, and the uid 10
#Removes any &= characters in the input email
def profile_for(email):
	strippedEmail = email.replace("=", "").replace("&", "")
	profile = KVObject()
	profile.addKV("email", strippedEmail)
	profile.addKV("uid", 10)
	profile.addKV("role", "user")
	return profile.serialize()

persistentKey = ""

#Generates an encrypted serialized profile for the given string
def encrypted_profile_for(email):
	global persistentKey
	if persistentKey == "":
		persistentKey = ecboracle.generateRandomKey()
	return aes.aesECBEncrypt(profile_for(email), persistentKey)

#Creates a profile object from the encrypted string
def decrypt_profile(profileString):
	global persistentKey
	return KVObject(aes.aesECBDecrypt(profileString, persistentKey))
