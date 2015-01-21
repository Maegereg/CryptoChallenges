import convert
import diffiehellman as dh
import hash
import random
import socket
import srp
import threading

class ModifiedSRPClient(srp.SRPClient):
	'''
	Returns true if logging in to the given server with the given username and password succeeds
	'''
	def login(self, ip, port):
		sendSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sendSocket.connect((ip, port))

		privateKey = srp.generatePrivateKey()
		
		sendSocket.send(str(self.username)+","+str(srp.generateClientPublicValue(privateKey)))

		salt, serverPublicValue, u = self.recieveServerValues(sendSocket)
		if salt is None or serverPublicValue is None or u is None:
			sendSocket.close()
			return False

		x = srp.getHashInt(self.password+salt)
		sharedSecret = pow(serverPublicValue, (privateKey+u*x), srp.STANDARD_N)
		sharedSecret = convert.intToByteString(hash.sha256(convert.intToByteString(sharedSecret)))
		validator = srp.generateClientValidator(sharedSecret, salt)
		sendSocket.send(str(validator))

		if self.recieveOK(sendSocket):
			sendSocket.close()
			return True
		sendSocket.close()
		return False

	'''
	Recieves the server's public value and salt from the given socket.
	Returns a tuple of salt, public value
	Returns None, None if something goes wrong
	'''
	def recieveServerValues(self, recieveSocket):
		try:
			data = recieveSocket.recv(1024)
			splitData = data.split(",")
			return (convert.intToByteString(int(splitData[0])), int(splitData[1]), int(splitData[2]))
		except Exception as e:
			return (None, None, None)

class ModifiedSRPServer(srp.SRPServer):
	def runServer(self):
		#Socket setup
		recieveSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		recieveSocket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR, 1)
		recieveSocket.bind(("", self.port))

		recieveSocket.listen(5)

		#Establish connection
		clientSock, _ = recieveSocket.accept()

		userName, clientPublicValue = self.recieveClientValues(clientSock)
		#Error case
		if userName is None or clientPublicValue is None:
			return

		passwordVerifier, salt = self.users[userName]
		sessionPrivateKey = srp.generatePrivateKey()

		u = random.randint(0, 2**128)

		#Send public values
		clientSock.sendall(str(convert.byteStringToInt(salt))+","+str(dh.generatePublicValue(sessionPrivateKey, srp.STANDARD_G, srp.STANDARD_N))+","+str(u))

		#Derive shared secret
		sharedSecret = pow(clientPublicValue*pow(passwordVerifier, u, srp.STANDARD_N), sessionPrivateKey, srp.STANDARD_N)
		sharedSecret = convert.intToByteString(hash.sha256(convert.intToByteString(sharedSecret)))

		clientValidator = self.recieveClientValidator(clientSock)
		#Error check
		if clientValidator is not None:
			if clientValidator == srp.generateClientValidator(sharedSecret, salt):
				clientSock.sendall("OK")
				return

		try:
			clientSock.sendall("NOTOK")
		except Exception:
			pass


class AttackSRPServer(ModifiedSRPServer):
	def runServer(self):
		#Socket setup
		recieveSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		recieveSocket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR, 1)
		recieveSocket.bind(("", self.port))

		recieveSocket.listen(5)

		#Establish connection
		clientSock, _ = recieveSocket.accept()

		userName, clientPublicValue = self.recieveClientValues(clientSock)
		#Error case
		if userName is None or clientPublicValue is None:
			return

		salt = srp.generateRandomSalt()
		sessionPrivateKey = srp.generatePrivateKey()

		u = random.randint(0, 2**128)

		#Send public values
		clientSock.sendall(str(convert.byteStringToInt(salt))+","+str(dh.generatePublicValue(sessionPrivateKey, srp.STANDARD_G, srp.STANDARD_N))+","+str(u))

		#Get validator
		clientValidator = self.recieveClientValidator(clientSock)

		#We're not actually checking the password
		clientSock.sendall("OK")

		#Function to check that the password will produce a matching validator
		checkPassword = lambda password: self.generateClientValidator(password, salt, clientPublicValue, sessionPrivateKey, u) == clientValidator

		'''
		#Assume the password is made up only of printing ascii characters
		initialChar = 32
		finalChar = 126
		
		#Check all possible passwords - this is really, really, slow. 
		password = [initialChar]
		passwordLen = 1
		while not checkPassword("".join(map(chr, password))):
			if password == [finalChar]*passwordLen:
				passwordLen += 1
				password = [initialChar]*passwordLen
			else:
				index = passwordLen-1
				while(password[index] == finalChar):
					password[index] = initialChar
					index -= 1
				password[index] += 1

		print "".join(map(chr, password))
		'''

		#Altarnatively, a dictionary attack
		passwordFile = open("10k most common.txt")
		for line in passwordFile:
			line = line.rstrip()
			if checkPassword(line):
				print line
				return

		


	def generateClientValidator(self, password, salt, clientPublicValue, serverPrivateKey, u, debug = False):
		passwordVerifier = srp.generatePasswordVerifier(password, salt)
		sharedSecret = pow(clientPublicValue * pow(passwordVerifier, u, srp.STANDARD_N), serverPrivateKey, srp.STANDARD_N)
		sharedSecret = convert.intToByteString(hash.sha256(convert.intToByteString(sharedSecret)))
		return srp.generateClientValidator(sharedSecret, salt)

if __name__ == "__main__":
	server = ModifiedSRPServer(50000)

	server.addUser("steve", "password")

	serverThread = threading.Thread(target=server.runServer)
	serverThread.start()

	client = ModifiedSRPClient("steve", "password")
	client.login("localhost", 50000)

	server = AttackSRPServer(50000)

	serverThread = threading.Thread(target=server.runServer)
	serverThread.start()

	client = ModifiedSRPClient("steve", "letsgo")
	client.login("localhost", 50000)
