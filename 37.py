import convert
import hash
import socket
import srp
import threading

class MaliciousSRPClient(srp.SRPClient):
	def __init__(self, username, publicValue, sharedSecretValue):
		self.username = username
		self.publicValue = publicValue
		self.sharedSecretValue = sharedSecretValue

	'''
	Returns true if logging in to the given server with the given username and password succeeds
	'''
	def login(self, ip, port):
		sendSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sendSocket.connect((ip, port))
		
		sendSocket.send(str(self.username)+","+str(self.publicValue))

		salt, serverPublicValue = self.recieveServerValues(sendSocket)
		if salt is None or serverPublicValue is None:
			sendSocket.close()
			return False

		sharedSecret = convert.intToByteString(hash.sha256(convert.intToByteString(self.sharedSecretValue)))
		validator = srp.generateClientValidator(sharedSecret, salt)
		sendSocket.send(str(validator))

		if self.recieveOK(sendSocket):
			sendSocket.close()
			return True
		sendSocket.close()
		return False

if __name__ == "__main__":
	server = srp.SRPServer(50000)

	server.addUser("steve", "password")

	serverThread = threading.Thread(target=server.runServer)
	serverThread.start()

	client = MaliciousSRPClient("steve", 0, 0)
	print client.login("localhost", 50000)

	server = srp.SRPServer(50000)

	server.addUser("steve", "password")

	serverThread = threading.Thread(target=server.runServer)
	serverThread.start()

	client = MaliciousSRPClient("steve", srp.STANDARD_N, 0)
	print client.login("localhost", 50000)

	server = srp.SRPServer(50000)

	server.addUser("steve", "password")

	serverThread = threading.Thread(target=server.runServer)
	serverThread.start()

	client = MaliciousSRPClient("steve", srp.STANDARD_N*2, 0)
	print client.login("localhost", 50000)