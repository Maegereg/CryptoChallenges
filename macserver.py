import mac
import web
from time import sleep

urls = ('/', 'index')
key='conquer'

def insecureCompareStrings(str1, str2):
	for i in range(len(str1)):
		if i >= len(str2):			return False
		if str1[i] != str2[i]:
			return False
		sleep(0.05)
	return True


'''
It was probably intended that the file argument actually be used as the name of a file to be MACed,
but the principle is the same
'''

class index:
	def GET(self):
		args = web.input(signature=None, file=None)
		if args.file is not None and args.signature is not None:
			if insecureCompareStrings(hex(mac.hMAC_SHA1(str(args.file), key))[2:-1], args.signature):
				return "Signature verified"
		raise Exception
		

if __name__ == "__main__":
	web.config.debug=False
	app = web.application(urls, globals())
	app.run()