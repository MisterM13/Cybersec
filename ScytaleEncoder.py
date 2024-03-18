#######################################################
#                                                     #
#                   Skytale Encoder                   #
#                    by MisterM13                     #
#             (https://github.com/misterm13)          #
#                                                     #
#      This Application demostrates how               #
#      the Scytale Encryption can easily be broken.   #
#      For educational purpose only, may be freely    #
#      shared and modified. More infos about skytale: #
#      https://en.wikipedia.org/wiki/Scytale          #
#                                                     #
#######################################################

enctext = "a rfuttoontowrram eicob skrese"
l = len(enctext)
print(l)

def decrypt(dist):
	i = int(l/dist)
	t = [""]*i
	for j in range(0,l):
		t[j%i]+= enctext[j]
		#print(t)
	dectext = "".join(t)
	print(dist,":",dectext)
	

for i in range(1,l):
	decrypt(i)