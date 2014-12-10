from convert import *
import sys
import englishscore

'''
Key: Terminator X: Bring the noise
Message:
I'm back and I'm ringin' the bell 
A rockin' on the mike while the fly girls yell 
In ecstasy in the back of me 
Well that's my DJ Deshay cuttin' all them Z's 
Hittin' hard and the girlies goin' crazy 
Vanilla's on the mike, man I'm not lazy. 

I'm lettin' my drug kick in 
It controls my mouth and I begin 
To just let it flow, let my concepts go 
My posse's to the side yellin', Go Vanilla Go! 

Smooth 'cause that's the way I will be 
And if you don't give a damn, then 
Why you starin' at me 
So get off 'cause I control the stage 
There's no dissin' allowed 
I'm in my own phase 
The girlies sa y they love me and that is ok 
And I can dance better than any kid n' play 

Stage 2 -- Yea the one ya' wanna listen to 
It's off my head so let the beat play through 
So I can funk it up and make it sound good 
1-2-3 Yo -- Knock on some wood 
For good luck, I like my rhymes atrocious 
Supercalafragilisticexpialidocious 
I'm an effect and that you can bet 
I can take a fly girl and make her wet. 

I'm like Samson -- Samson to Delilah 
There's no denyin', You can try to hang 
But you'll keep tryin' to get my style 
Over and over, practice makes perfect 
But not if you're a loafer. 

You'll get nowhere, no place, no time, no girls 
Soon -- Oh my God, homebody, you probably eat 
Spaghetti with a spoon! Come on and say it! 

VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino 
Intoxicating so you stagger like a wino 
So punks stop trying and girl stop cryin' 
Vanilla Ice is sellin' and you people are buyin' 
'Cause why the freaks are jockin' like Crazy Glue 
Movin' and groovin' trying to sing along 
All through the ghetto groovin' this here song 
Now you're amazed by the VIP posse. 

Steppin' so hard like a German Nazi 
Startled by the bases hittin' ground 
There's no trippin' on mine, I'm just gettin' down 
Sparkamatic, I'm hangin' tight like a fanatic 
You trapped me once and I thought that 
You might have it 
So step down and lend me your ear 
'89 in my time! You, '90 is my year. 

You're weakenin' fast, YO! and I can tell it 
Your body's gettin' hot, so, so I can smell it 
So don't be mad and don't be sad 
'Cause the lyrics belong to ICE, You can call me Dad 
You're pitchin' a fit, so step back and endure 
Let the witch doctor, Ice, do the dance to cure 
So come up close and don't be square 
You wanna battle me -- Anytime, anywhere 

You thought that I was weak, Boy, you're dead wrong 
So come on, everybody and sing this song 

Say -- Play that funky music Say, go white boy, go white boy go 
play that funky music Go white boy, go white boy, go 
Lay down and boogie and play that funky music till you die. 

Play that funky music Come on, Come on, let me hear 
Play that funky music white boy you say it, say it 
Play that funky music A little louder now 
Play that funky music, white boy Come on, Come on, Come on 
Play that funky music 

'''

#Finds the best repeating xor key for an encrypted message (assuming len(key) < 50)
def getXorKey(bytes, keySize = -1):
	if keySize < 0:
		keySize = findKeySize(bytes)
	key = ""
	for i in range(keySize):
		key = key+englishscore.findSingleXorKey(bytes[i::keySize])[0]
	return key

#Finds the best repeating xor key size for an excrypted message (assuming len(key) < 50)
def findKeySize(bytes):
	minEditDistance = sys.maxint
	bestKeySize = 0
	for keysize in range(1, 50):
		editDistance = getAverageEditDistance(keysize, bytes)
		if minEditDistance > editDistance:
			minEditDistance = editDistance
			bestKeySize = keysize
	return bestKeySize

#Breaks the input bytes into chunks of size keysize and returns the average hamming distance between non-overlapping pairs of consecutive chunks
def getAverageEditDistance(keysize, bytes):
	if len(bytes) < 2*keysize:
		return sys.maxint
	else:
		curstart = 0
		curend = keysize*2
		compared = 0
		totalHamming = 0
		while curend < len(bytes):
			totalHamming += hammingDistance(bytes[curstart:curstart+keysize], bytes[curstart+keysize:curend])
			compared += 1
			curstart = curend
			curend += 2*keysize
		return float(totalHamming)/(compared*keysize)

#Calculates the hamming distance between two byte string
def hammingDistance(bytes1, bytes2):
	distSum = 0
	for i in range(len(bytes1)):
		byte1 = ord(bytes1[i])
		byte2 = ord(bytes2[i])

		while byte1 > 0 or byte2 > 0:
			distSum += (byte1 & 1) != (byte2 & 1)
			byte1 = byte1 >> 1
			byte2 = byte2 >> 1
	return distSum

#Performs exercise 6 - decrypts the buffer in the file below
def ex6():
	inFile = open("6.txt")
	text = ""
	for line in inFile:
		text = text + line
	inFile.close()
	text = b64ToByteString(text.replace("\n", ""))

	key = getXorKey(text)
	print "key: ", key

	message = englishscore.repeatedXor(key, text)

	print "message: ", message

	#print hammingDistance("this is a test", "wokka wokka!!!")


if __name__ == "__main__":
	ex6()