#	listMaker.py pulls known malicious sites from malwaredomainlist.com and zeustracker.abuse.ch 
#   and creates a list in bro language to fire off a Sensitive URI email whenever any of the sites are accessed. 
#   Everytime this script is run it sends and email to the IT department notifying the new additions/removals of malicious sites.


import urllib
import time
import smtplib
import string
from email.mime.text import MIMEText
from subprocess import call

#Main function holds all of the steps to the program
def main():
	theList = []			#Create the list
	malwareGatherer(theList)	#Populate it with sites from malware gatherer
	zeusGatherer(theList)		#and zeus tracker
	manualListGatherer(theList)	#and sites known to us 
	
	d = open(path + "listMakeTest.txt", 'w')	#save the data to a file
	listMaker(d, theList)
	d.close()

	d = open(path + "listMakeTest.txt", 'r')	#compare that file with the results of the list from that time
	e= open(path + "listMakerCompare.txt", 'r')
	compare(d,e)
	d.close()
	e.close()

	d = open(path + "listMakeTest.txt", 'r').read()	#rewrite the old list with the new one
	e = open(path + "listMakerCompare.txt", 'w')
	e.write(d)
	
	copyFile("finalList.txt")			#Add the list to the bro arcitecture
	restartBro()					

	sendEmail(path + "newAdditions.txt")		#Send email with new additions/removals of malicious sites



#Takes the known malicious sites and forms them into a pattern in Bro-code
def listMaker(d, theList):
	top= open(path + "top.txt", 'r').read()
	bottom= open(path + "bottom.txt", 'r').read()
	finalList= open(path + "finalList.txt", 'w')	

	theList.sort()
	
	omissions = open("/usr/local/bro/scripts/dns/stripoutfile.bin").readlines() 	#Take out any that we have identified as false positives
	for i in omissions:
		value = i.split()
		if theList.count(value[0]) != 0:
			theList.remove(value[0])
	
	finalList.write(top)

	for i in range(0, len(theList) - 1):
		d.write(theList[i] + "\n")
		finalList.write("\t\t\t/^" + theList[i] + "/ |\n")
	
	finalEntry = theList[len(theList) - 1]
	finalList.write("\t\t\t/^" + finalEntry + "/\n")
	finalList.write(bottom)
	

#Gets all the info from malware domain list
def malwareGatherer(theList):
	site = urllib.urlopen("http://www.malwaredomainlist.com/hostslist/hosts.txt")
	site.readline()
        site.readline()
        site.readline()
        site.readline()
        site.readline()

        lines =  site.readlines()
	for i in lines:
		value = i.split()
		theList.append(value[1])

#Gets all the info from zeus tracker		
def zeusGatherer(theList):
	site = urllib.urlopen("https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist")
	
	site.readline()
	site.readline()
	site.readline()
	site.readline()
	site.readline()
	site.readline()
	
	lines = site.readlines()
	for i in lines:
		value = i.split()
		theList.append(value[0])

#Gets all the info from other known malicious domains
def manualListGatherer(theList):
	manualList = open("/usr/local/bro/scripts/dns/manuallist.txt")
	
	lines = manualList.readlines()
	for i in lines:
		value = i.split()
		theList.append(value[0])

#Comapres the newly generated list from the list generated the last time this program was executed
def compare(d, e):
        c= open(path + "newAdditions.txt", 'w')
        c.write("----------Malicious Domains Added.----------\n\n")

        dEntries = d.readlines()
        eEntries = e.readlines()

        for i in dEntries:			#domains that were added
                if eEntries.count(i) == 0:
                        c.write(i)

        c.write("\n\n-------------Malicious Domains Removed--------------\n\n")
        for i in eEntries:			#domains that ere removed
                if dEntries.count(i) == 0:
                        c.write(i)


def sendEmail(daFile):
	brackets = open(daFile, 'r').readlines()
	counter = 0
	for i in brackets:
		if "www." in brackets[counter]:						#Make sure that outlook doesnt form any hotlinks, we dont want people clicking on them!	
			brackets[counter] = brackets[counter].replace("www.", "www[.]")	
		counter = counter + 1
	replace = open(daFile, 'w')
	for i in brackets:
		replace.write(i)
	replace.close()
	
        sender = 'Bro-DNS-List@zenimax.com'
			# --------------- Change this to your email address
        receivers = ['you@email.com']
        fp = open(daFile, 'rb')
        msg = MIMEText(fp.read())
        fp.close()

        msg['Subject'] = 'Bro Sensor - Malicious DNS Update'
        msg['From'] = sender
        msg['To'] = ', '.join(receivers)
			# -------------- Change this to your email server
        s = smtplib.SMTP('emailserver.server.com')
        s.sendmail(sender, receivers, msg.as_string())
        s.quit()

def restartBro():
	call([bropath + "broctl", "install"])
	call([bropath + "broctl", "restart"])
		
#Copies the bro file to the proper bro directory
def copyFile(filename):
	call(["cp", path + filename, "/usr/local/bro/share/bro/policy/protocols/dns/new-dns.bro"])	


bropath = "/usr/local/bro/bin/"		
path = "/usr/local/bro/scripts/dns/pythonScripts/"
main()
