#!/usr/bin/env python3
import time

# Educational Example of a Time based weak Authentification
# -> application processes solution char after char, correct chars have longer to analyse

corrPass = "Hello World"  #Password
isCorr = True
processingTime = 0.05	# time to mach the letter with password


#Rejecting function
def falsePass():
	global isCorr
	isCorr = False
	print("Password incorrect !!!")

#Accepting function
def truePass():
	print("Successfully logged in!")

# function to fit the length of Input with Password
def fillLen(passInput):
	global corrPass
	while(len(passInput)<len(corrPass)):
		passInput+="-"
	return passInput

#This Function represents an Application, which processes each character after character using som time (processing Time) to process if it is correct. If not it rejects imideatly. So we can measure on the time if we got an char right.
def auth(passInput):
	global processingTime
	global isCorr
	global corrPass
	res = False
	passInput = fillLen(passInput)
	#print("auth: ",passInput,corrPass)
	for i in range(0,len(corrPass),1):
		if(corrPass[i]!=passInput[i]):
			falsePass()
			break
		else:
			isCorr = True
		time.sleep(processingTime)
	if (isCorr):
		truePass()
		res = True
	return res

#interactive authentification
def authInteractive():
	auth(input("please insert the password:"))

# Function representing a bruteforce attack using the time knowdlege.
def timeBruteforcer():
	pT = processingTime * 1000
	dict = " 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"  #Dictionary 
	j = 0
	x =""
	found = False
	while j < 100:
		ret = True
		for i in range(0,len(dict),1):
			j+=1
			inp = x+dict[i]
			a = time.time()*1000
			ret = auth(inp)
			b = time.time()*1000
			print("try:",inp,"time:",b-a,"ms")
			if(b-a > pT*len(inp)):
				if(ret):
					print("\n------------------------------")
					print("Password found:", x+dict[i])
					print("------------------------------")
					j = 100
					found = True
				else:
					x +=dict[i]
					j = 0
					#print(x, auth(x))
				break
	if(not found):
		print("\n------------------------------------------------------------------")
		print("it seems the Password was not found and the Bruteforcer timed out.\n")
		print("Possible Reasons:")
		print("1. Maybe the Bruteforcer doesn't use all chars which are in the Password")
		print("2. Maybe the processingTime is too short, which leads to Bruteforcer mistakes")


timeBruteforcer()