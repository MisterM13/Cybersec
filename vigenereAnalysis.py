#!/usr/bin/env python3

#############################################################
#                                                           #
#                Vigenère Analysis Program                  #
#                   made by misterm13                       #
#             (https://github.com/misterm13)                #
#                                                           #
#   Used to analyse a Vigenère encrypted text and           #
#   probably decrypt it. Program designed in the process    #
#   of solving the Vigenère encoded text, in context of     #
#   exercises of the Cyber Security course, by Dr. Wagner,  #
#   at Unibas. As it was written in process it might not    #
#   be a perfect code and have also some rough edges and    #
#   code inside used for different approach to solve it.    #
#   This code is for educational purpose only. It may be    #
#   changed, used for further development and shared for    #
#   free. It shows how Vigenère Cipher code can be broken,  #
#   with a bit of luck.                                     #
#   more infos about Vigenère Cipher:                       #
#   https://en.wikipedia.org/wiki/Vigenère_cipher           #
#                                                           #
#                                                           #
#############################################################

encText = "XEUBZWGDIKHNOFMIGUQBQZSLYGHUJRWPAABWELYCHUNNLOQGFYALLUSAYTZHVCAJWGBTRYNKWAWOQRILAWOFYUVLVHBKCGTXIGJRKLKIENTQZMQHWILFJIMEWGYLGPTMWHVRTTWAAPCHYDGBJHFJCMYQHLURGMMGFNOFHTGNSDKLKIENTQYMGRFRUOMFFHAFWZCSNTXYWAQWOHWQBTYHWYQUUYBMGHKBWDSABVRWIYOBHVREKAQZYYHAZJCBPIKUWHVSTWULSQFSSMIGUNOFNCWQJTZPAWFFTWEBPBTKGUKCZUULLZGRHUJPBMNYEPAJCBPHSZBCPTNNLGHUJFMULOZJNLHTDENNUPXZRXOXPBGQNSUPXZVSEAUBVVXSHPZWGYHWHBHRRPLOIGOJEFTIRRYOWEBFNHTWZASAYISSQRRFSLOIHHSDWYXWAYHWWTSGMOJHWTFJCMYQHLREUOIBVXMKVVSSNNVZLSCQOQLLWAYOVHGGVYLSULGPFPWHBSKYBGVSGUTUDKIZFTIFZBFHHTLOMFRFDWYEVRSAFKPCJYOSWXZLYHWZMTHSDSTMBGFLHYQBPNPDLAOFYHWPBZNSDKJIDRPEWWAQUFNYPVUFJCMYQHLURSJBWGNOFLZGUFVWAWIAIEJZBOAIWZLVTNRIDPIFFJCMYQHLREUOIBVXMKUWZBSGWYIRQWEKZVSJQYWTMFTNNYAPFRFTKVNQBZRKLBVRDADZWVNAELVCBQJRKAIBQMOOAWOCULQAPSFJCMYQHLREUOIBVXMKHBHUJIJKQGCTSSS"
#encText = "VVHUWWFODFRAPTRBLIPTUCYITHKINOCCFCJEPRUYPGLRVCWLGGXRUSWAKHKSWHOSQYLRIPDGMOWXJSSEUHRVEOUIUCIXJSGEAPHGCIVIKHLWGOJITZBEYOLXKBJJQFWLGBHBVQKERHHVQTOMHSLRVVHYPYQSYBWITFLXQFBSHVRTGOQHFFHEOGZLKQKETSQIXSUWQQOICFEYVTRVGJHVRFHWGBWMPHKIJSDVVGRJVVRWGKKSUSHOVVHQYWWLHOLXJOQHFSWITALRCHLSP" # sample 1 encoded with "CODE"
#encText = "KBWLGVHETHRJCPXWVZLRIQLXAKKITSWLGGNCUQUERSUWMWVWGRWLGQOSWRVEPRWLGGWVGSWWJIPQGRZMVVWLGFKCVVPSHZLJGHKITSVXQCGESIDMPHOMVHOIDCROUHRVGWWWYCRHGBVLGZYIUKHVGZDHGBZMVVESQYVSHSYITMJIPFHXJSLVUDLRGGFVCQNIFOQHROJIUMHPNCZIFKLXJOJIVVHWESQXQTRPFDDTGFDRFWQOJIQKJSDZAWQXJSDMTKHPECPMPUEMDZLSRVLPGGDRFKDRFSUITGDPKYHMPHRMVGFSBMHQDFDGGOPMFGWLGQKEQGRJVVHQGHUSRCOMUHKMUPRSMGWSTSZEUOQSCGLWQTFENAD" # sample 2 encoded with "CODE"
decSample = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOGANDRUNSINTOTHESUNSETWITHOUTLOOKINGBACKATTHEPASTORCARESOFTHEDAYBECAUSEITISEAGERLYAWAITINGFORTHENEXTCHAPTEROFLIFEINTHEUNKNOWNTERRITORYOFHOPEANDDREAMSWHICHARENEVERSOCLEARBUTFOREVERPRESENTINTHEHEARTSOFTHOSEWHOSEEKTHEMWITHFAITHANDDETERMINATION" # sample 1 decoded

totalcount = len(encText) # -> 795 = 15*53
keylen = 15
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"	

#frequency patterns:
#basic order of Probabilities of the letters in the english (and german) alphabet
engFreqAl = "ETAOINSHRDLCUMWFGYPBVKJXQZ"	
deuFreqAl = "ENISRATDHULCGMOBWFKZPVJYXQ"

#as the text normally doesn't apply good to the basic probabilities, i made some substitutions, to get more certainity
freq = ["ETAOINSHRDLCUMWFGYPBVKJXQZ","ENISRATDHULCGMOBWFKZPVJYXQ","TEAOINSHRDLCUMWFGYPBVKJXQZ","TAEOINSHRDLCUMWFGYPBVKJXQZ","TAOEINSHRDLCUMWFGYPBVKJXQZ","TAOIENSHRDLCUMWFGYPBVKJXQZ","TAOINESHRDLCUMWFGYPBVKJXQZ","TAOINSEHRDLCUMWFGYPBVKJXQZ","ATEOINSHRDLCUMWFGYPBVKJXQZ","AETOINSHRDLCUMWFGYPBVKJXQZ","TEOANISHRDLCUMWFGYPBVKJXQZ","TEOANIHSDRCLUMWFGYPBVKJXQZ","TEOANIHSDRCLMUFWYGPBVKJXQZ","ETORANHISFUWDCPLKYMGBVXZQJ","EOTRANHISFUWDCPLKYMGBVXZQJ","ETROANHISFUWDCPLKYMGBVXZQJ","ETAORNHISFUWDCPLKYMGBVXZQJ","TESIAONRHDUCPLMYFGWBKZXVQJ"]
candidates = []

#counts the frequency of certain letters in the text in relation to the length of text and orders it
#ex:  countlist[0]: (30.123, "E") -> probability, letter
def getcount(text):
	countlist = []
	for i in alphabet:
		l = 0
		for j in text:
			if j == i:
				l+=1
		countlist.append(((l/len(text))*100,i))
		#print(i, (l/len(text))*100)
	
		#print("\n\n")
	countlist.sort(reverse=True)
	#for c in countlist:
		#print(c[1],c[0])
	return countlist

#does not work as every letter is different encrypted (DEPRECIATED, see solveCountFreqKey(text,countlist,freq))
def solveCountFreq(numOfLetters,text,countlist):
	keyword = " "*keylen
	copyText = list(text)
	for i in range(0,numOfLetters):
		pair = countlist[i]
		lenc = pair[1]
		ldec = engFreqAl[i]
		#ldec = deuFreqAl[i]
		for j in range(0,len(text)):
			if copyText[j]  == lenc:
				keyword = keyword[0:j] + getkeyletter(lenc,ldec) + keyword[(j+1):totalcount]
				copyText[j] = "\x1b[0;33;40m"+ ldec+ "\x1b[0m"
				ctext = "".join(copyText)
	print(ctext)
	print(keyword)

# returns an array candidate letters
def solveCountFreqKey(text,countlist,freq):
	k = ""
	for i in range(0,26):
		pair = countlist[i]
		lenc = pair[1]
		ldec = freq[i]
		#ldec = deuFreqAl[i]
		for j in range(0,len(text)):
			if text[j]  == lenc:
				k += getkeyletter(lenc,ldec) #calculates possible cand. letter
	k = list(k)
	k.sort()
	k = "".join(k)
	#print(k)
	return k

# returns the key letter, input: encrypted letter, decrypted letter
def getkeyletter(lenc,ldec):
	x = "_"
	for a in alphabet:
		#ldec == (lenc - keyword[j] + 26) % 26 + 'A';
		if ord(ldec) == (ord(lenc) - ord(a) + 26) % 26 + ord('A'):
			x = a
	return x

#splits the list in pieces of the keylen, then every column is one text
#so every letter encoded with the same key can be frequency analysed
def getCutlist(length):
	cutList = ""
	columns = [""]*length
	c = 0
	for i in encText:
		c+=1
		cutList += i
		columns[c-1] += i
		if c%length == 0:
			cutList +="\n"
			c=0
			
			#print(cutList)
			#print(columns)
	return((cutList,columns))

#analyses each column
def getCountFreq(columns):
	frequencies = [0]*len(columns)
	for c in range(0,len(columns)):
		#print(columns[c])
		frequencies[c] = getcount(columns[c])
	return (columns,frequencies)

# decodes the text with the vigniere method
def tryKey(key):
	decText = ""
	for i in range(0,len(encText)):
		decText += chr((ord(encText[i])-ord(key[i%len(key)])+26)%26+ord("A"))
		#print(decText)
	return decText

# derives the best maching key (probability) for a certain keylen and frequency pattern
# returns possible key candidate with each letter special highlighted related to the probability that it may be the right letter
# So we can determine by hand what the key could be
def deriveKey(keylen,freq):
	(cutList,columns) = getCutlist(keylen)
	(columns,frequencies) = getCountFreq(columns)
	
	candidates = [""]*keylen
	for i in range(0,keylen):
		candidates[i] = solveCountFreqKey(columns[i],frequencies[i],freq)
	keyCand = getCountFreq(candidates)
	#print(keyCand)
	
	key = ""
	for c in keyCand[1]:
		cand = c[0]
		if cand[0] > 30:	#probability highlighting:
			key += "\x1b[0;37;42m"+ cand[1]+ "\x1b[0m"	#30% white, green background
		elif cand[0] > 22:
			key += "\x1b[0;33;40m"+ cand[1]+ "\x1b[0m" #22% yellow
		elif cand[0] > 20:
			key += "\x1b[0;36;40m"+ cand[1]+ "\x1b[0m" #20% cyan
		elif cand[0] > 18:
			key += "\x1b[0;35;40m"+ cand[1]+ "\x1b[0m" #18% pink/rosa
		elif cand[0] > 16:
			key += "\x1b[1;31;40m"+ cand[1]+ "\x1b[0m" #16% red
		else:
			key += cand[1]
	#print(key)
	return key


#for i in range(1,54):
#	key = deriveKey(i,20)
#	tryKey(key)
#	print(i,key)

#tries a key to encrypt and if E is the most used char in the encrypted text
#the key and text get added in candidates -> used for the bruteforce way
def tryAndAddKey(key):
	#print("trying key:",key)
	global candidates
	text = tryKey(key)
	countlist = getcount(text)[0]
	if countlist[1] == "E":
		print("Found:",key)
		candidates.append(key)
		candidates.append(text)

# try to bruteforce the keys, but doesn't work well, as there are still too many candidates
def bruteforce(keylen):
	wordspace = [0]*keylen
	generatedKey = ""
	i = 0
	while i < keylen:
		generatedKey = ""
		for w in wordspace:
			#print(w)
			generatedKey += alphabet[w]
		#mirror = generatedKey[::-1]
		tryAndAddKey(generatedKey)
		#tryAndAddKey(mirror)
		
		if wordspace[i]+1 <26:
			wordspace[i]+=1
			i = 0
		else:
			i+=1
			for j in range(0,i):
				wordspace[j] = 0
				#print(generatedKey)
	print(candidates)

	#bruteforce(4)
#countlist = getcount(tryKey("CODE"))[0]
#print(countlist[1])


print("\x1b[0;37;42m > 30% Probability \x1b[0m")	
print("\x1b[0;33;40m > 22% Probability \x1b[0m")
print("\x1b[0;36;40m > 20% Probability \x1b[0m")
print("\x1b[0;35;40m > 18% Probability \x1b[0m")
print("\x1b[1;31;40m > 16% Probability \x1b[0m \n")

for i in freq:
	print(deriveKey(7,i))
	
#print(tryKey("CODE"))
