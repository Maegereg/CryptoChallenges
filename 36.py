import srp
import threading

if __name__ == "__main__":
	server = srp.SRPServer(50000)

	server.addUser("steve", "password")

	serverThread = threading.Thread(target=server.runServer)
	serverThread.start()

	client = srp.SRPClient("steve", "password")
	print client.login("localhost", 50000)