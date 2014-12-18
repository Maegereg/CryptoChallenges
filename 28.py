import mac

if __name__ == "__main__":
	MAC = mac.sha1KeyPrefix("The East Grestin border checkpoint is now open. All applicants must have a passport.", "Glory to Arstotzka!")
	print MAC
	print mac.verifySha1KeyPrefix("The East Grestin border checkpoint is now open. All applicants must have a passport.", "Glory to Arstotzka!", MAC)