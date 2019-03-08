#!/usr/bin/env python3

"""
@Author Razvan Raducu
"""

# pip install requests
import requests 
import json
import sys
import os

def printUsage():
	print("Usage:\n"+
		"Execute it with command \"./PythonSonarBot.py\". Make sure it has execute permission.\n"+
		"The script receives the following arguments: \n"+
		"\tThe directory you want the sourcecode to be downloaded in. Example: ./PythonSonarBot.py ./DataSet\n"+
		"The script receives the following options: \n"+
		"\tNo option. When no option is specified it will execute in quiet mode.\n"+
		"\t-v option is used for verbose mode. Example: ./PythonSonarBot ./DataSet -v\n")
	sys.exit()

def checkPath(path):
	if not os.path.exists(path):
		try:
			os.makedirs(path)
		except OSError as err:
			print("Error: {0}".format(err))
			sys.exit()


############################↓↓↓ Detecting arguments and options ↓↓↓######################################
print("#### Append -h to print usage. (./PythonSonarBot.py -h) ####\n")
verbose = 0
dumpDir = ""
if len(sys.argv) == 2:
	if sys.argv[1] == '-h':
		printUsage()
	else:
		dumpDir = sys.argv[1]
		checkPath(dumpDir)
elif len(sys.argv) == 3: 
	if sys.argv[2] == '-v': verbose +=1 
	else:
		print("Wrong usage. Aborting")
		sys.exit() 
	dumpDir = sys.argv[1]
	checkPath(dumpDir)
else:
	print("Wrong usage. Aborting")
	sys.exit()

print("#### Executing verbosely") if verbose else print("#### Executing in quiet mode. ####")

verbosePrint = print if verbose else lambda k: None
############################↑↑↑ Detecting arguments and options ↑↑↑######################################

############################↓↓↓ Requesting project IDS ↓↓↓######################################
def APIProjectRequest():
	global remainingResults
	global queryJsonResponse

	url = 'https://sonarcloud.io/api/components/search_projects'
	parameters = {'filter':'security_rating>=2 and languages=c','p': p,'ps': ps }

	try:
		req = requests.get(url, params=parameters)
	except requests.exceptions.RequestException as e:
		print("Error: {0}".format(e))
		sys.exit()

	verbosePrint("#### Request made to " + req.url + " ####")

	# Writing the results of the query to a file
	queryJsonResponse = req.json()
	totalResults = queryJsonResponse['paging']['total']
	verbosePrint("#### Query generated " + str(totalResults) + " results ####")

	verbosePrint("#### Writing page " + str(p) + " to file ####")

	# The writing is done in 'a' (append) mode (optional)
	##print(json.dumps(queryJsonResponse, indent=4), file=open('sonarQueryResults.json','a'))

	remainingResults = totalResults - (ps*p)
	if remainingResults < 0:
		remainingResults = 0
	verbosePrint("#### There are " + str(remainingResults) + " left to #print ####")

p = 1
ps = 500
remainingResults = 0
queryJsonResponse = 0

APIProjectRequest()

while remainingResults > 500:
	if p == 20: # 500 results * 20 pages = 10000 limit reached
		break
	p+=1
	verbosePrint("#### Querying again. Requesting pageindex " + str(p) + " ####")
	APIProjectRequest()


#################################↑↑↑  Requesting project IDS  ↑↑↑################################

##################################↓↓↓ Requesting sourcecode ↓↓↓##################################

"""
When requesting sourcecode only the key is needed, as stated by the api DOCS 
https://sonarcloud.io/web_api/api/sources/raw. The key is ['issues']['component']
value from the queryJsonResponse at this moment.
"""

def APISourceCodeRequest():
	url = 'https://sonarcloud.io/api/sources/raw'

	# For each project ID, we get its source code and name it according to the following pattern:
	# fileKey_startLine:endLine.c

	with open('sonarQueryResults.json') as data_file:    
		data = json.load(data_file)

	for issue in data['issues']:
		fileKey = issue['component']
		parameters = {'key':fileKey}
		try:
			req = requests.get(url, params=parameters)
		except requests.exceptions.RequestException as e:
			print(e)
			print("Aborting")
			sys.exit(1)

		# If the file contains errors because it was not found, we simply skip it.
		if req.content.find(b"{\"errors\":[{\"msg\":") != -1:
			print("#### FILE " + req.url + " SKIPPED BECAUSE IT CONTAINS ERRORS ####\n")
			print(req.content)
			print("######################\n")
			continue

		# We replace '/' with its hex value 2F
		vulnerableFile = (str(dumpDir)+"/"+(str(fileKey)).replace('/','2F'))
		verbosePrint("Looking if "+ vulnerableFile+ " exists.")
		if not os.path.isfile(vulnerableFile):
			verbosePrint("++++> File doesn't exist. Creating <++++")
			with open(vulnerableFile, 'ab+') as file:
				file.write(req.content)
				file.write(str.encode("//\t\t\t\t\t\t↓↓↓VULNERABLE LINES↓↓↓\n\n"))
				file.write(str.encode("// " + str(issue['textRange']['startLine']) + "," + str(issue['textRange']['startOffset']) + ";" + str(issue['textRange']['endLine'])+ "," +str(issue['textRange']['endOffset']) +"\n\n"))
		else:
			verbosePrint("----> File exists. Appending vulnerable lines <----")
			with open(vulnerableFile, 'ab+') as file:
				file.write(str.encode("// "+ str(issue['textRange']['startLine']) + "," +  str(issue['textRange']['startOffset']) + ";" + str(issue['textRange']['endLine'])+ "," +str(issue['textRange']['endOffset']) +"\n\n"))

		
		

##################################↑↑↑ Requesting sourcecode ↑↑↑##################################

#################################↓↓↓ Requesting vulnerabilities ↓↓↓##############################
"""
Here are the keys of every single repo that meets the following conditions:
	1. Is public 
	2. Is written in C language
	3. Its security rating is >= 2
"""
projectIds = "" 
for component in queryJsonResponse['components']:
	# It's appended into the list to compose the following request.
	projectIds += str(component['key']) + ","

# Deletion of trailing comma. (Right side of index specifier is exclusive)
projectIds = projectIds[:-1]

p = 1
remainingResults = 0

def APIVulnsRequest():
	global remainingResults
	url = 'https://sonarcloud.io/api/issues/search'
	parameters = {'projects':projectIds, 'types':'VULNERABILITY', 'languages':'c', 'ps':ps, 'p': p }

	try:
		req = requests.get(url, params=parameters)
	except requests.exceptions.RequestException as e:
		print(e)
		print("Aborting")
		sys.exit(1)

	verbosePrint("#### Request made to " + req.url + " ####")

	# Writing the results of the query to a file
	queryJsonResponse = req.json()
	print(json.dumps(queryJsonResponse, indent=4), file=open('sonarQueryResults.json','w'))

	## REQUESTING SOURCECODE ##
	verbosePrint("#### REQUESTING SOURCECODE ####")
	APISourceCodeRequest()

	totalResults = queryJsonResponse['total']
	verbosePrint("#### Query generated " + str(totalResults) + " results ####")


	remainingResults = totalResults - (ps*p)
	if remainingResults < 0:
		remainingResults = 0
	verbosePrint("#### There are " + str(remainingResults) + " left to print ####")

APIVulnsRequest()

while remainingResults > 500:
	if p == 20: # 500 results * 20 pages = 10000 limit reached
		break
	p+=1
	verbosePrint("#### Querying again. Requesting pageindex " + str(p) + " ####")
	APIVulnsRequest()

###############################↑↑↑ Requesting vulnerabilities ↑↑↑################################
