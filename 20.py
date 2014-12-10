import aes
import convert
repeatXor = __import__('6')
import xor

def generateCiphertexts():
	plaintextFile = open("20.txt")
	ciphertexts = []
	key = aes.generateRandomKey()
	for line in plaintextFile:
		ciphertexts.append(aes.aesCTREncrypt(convert.b64ToByteString(line), key, 0))
	plaintextFile.close()
	return ciphertexts


def getMinLength(ciphertexts):
	return min(map(len, ciphertexts))

def breakRepeatingCTR(ciphertexts):
	minLength = getMinLength(ciphertexts)
	repeatedXorCiphertext = "".join(map(lambda x: x[:minLength], ciphertexts))
	key = repeatXor.getXorKey(repeatedXorCiphertext, minLength)
	return key

if __name__ == "__main__":
	ciphertexts = generateCiphertexts()
	key = breakRepeatingCTR(ciphertexts)
	for ciphertext in ciphertexts:
		print xor.xorByteStrings(ciphertext, key)

''' Plaintext (partial):
I'm rated "R"...this is a warning, ya better void / P
Cuz I came back to attack others in spite- / Strike l
But don't be afraid in the dark, in a park / Not a sc
Ya tremble like a alcoholic, muscles tighten up / Wha
Suddenly you feel like your in a horror flick / You g
Music's the clue, when I come your warned / Apocalyps
Haven't you ever heard of a MC-murderer? / This is th
Death wish, so come on, step to this / Hysterical ide
Friday the thirteenth, walking down Elm Street / You 
This is off limits, so your visions are blurry / All 
Terror in the styles, never error-files / Indeed I'm 
For those that oppose to be level or next to this / I
Worse than a nightmare, you don't have to sleep a win
Flashbacks interfere, ya start to hear: / The R-A-K-I
Then the beat is hysterical / That makes Eric go get 
Soon the lyrical format is superior / Faces of death 
MC's decaying, cuz they never stayed / The scene of a
The fiend of a rhyme on the mic that you know / It's 
Melodies-unmakable, pattern-unescapable / A horn if w
I bless the child, the earth, the gods and bomb the r
Hazardous to your health so be friendly / A matter of
Shake 'till your clear, make it disappear, make the n
If not, my soul'll release! / The scene is recreated,
Cuz your about to see a disastrous sight / A performa
Lyrics of fury! A fearified freestyle! / The "R" is i
Make sure the system's loud when I mention / Phrases 
You want to hear some sounds that not only pounds but
Then nonchalantly tell you what it mean to me / Stric
And I don't care if the whole crowd's a witness! / I'
Program into the speed of the rhyme, prepare to start
Musical madness MC ever made, see it's / Now an emerg
Open your mind, you will find every word'll be / Furi
Battle's tempting...whatever suits ya! / For words th
You think you're ruffer, then suffer the consequences
I wake ya with hundreds of thousands of volts / Mic-t
Novocain ease the pain it might save him / If not, Er
Yo Rakim, what's up? / Yo, I'm doing the knowledge, E
Well, check this out, since Norby Walters is our agen
Kara Lewis is our agent, word up / Zakia and 4th and 
Okay, so who we rollin' with then? We rollin' with Ru
Check this out, since we talking over / This def beat
I wanna hear some of them def rhymes, you know what I
Thinkin' of a master plan / 'Cuz ain't nuthin' but sw
So I dig into my pocket, all my money is spent / So I
So I start my mission, leave my residence / Thinkin' 
I need money, I used to be a stick-up kid / So I thin
I used to roll up, this is a hold up, ain't nuthin' f
But now I learned to earn 'cuz I'm righteous / I feel
Search for a nine to five, if I strive / Then maybe I
So I walk up the street whistlin' this / Feelin' out 
A pen and a paper, a stereo, a tape of / Me and Eric 
Fish, which is my favorite dish / But without no mone
'Cuz I don't like to dream about gettin' paid / So I 
So now to test to see if I got pull / Hit the studio,
Rakim, check this out, yo / You go to your girl house
'Cause my girl is definitely mad / 'Cause it took us 
Yo, I hear what you're saying / So let's just pump th
And count our money / Yo, well check this out, yo Eli
Turn down the bass down / And let the beat just keep 
And we outta here / Yo, what happened to peace? / Pea
'''