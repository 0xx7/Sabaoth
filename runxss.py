#Import custom libs, xss is the xss.py lib file, Xssrun and Payloads are the classes in xss.py
from xss import Xssrun #Variables used: xss
from xss import Payloads #Variables used: payload

#Importing time lib to do the time calculation
import time #Variables used: total_start,start,end,total_end
#Start counting
total_start = time.time()

#import termcolor lib
from termcolor import colored, cprint #Variables used: none

#Import general libs

#re is a regular expression lib in python, used to compare and verify strings
import re #Variables used: parameter_used
#Sys is system specific parameters and functions in python, used to run linux commands
import sys #Variables used: arguments,link,user_agent
#Requests is a http request lib, used to do the xss requests
import requests #Variables used: request

#Used to run linux commands
from os import system #variables used: check_site

#Start the xss quantity variable
xss_qtdy=0

#Define the fancy ASCII art to print on screeen =)
motd="""

  ██████  ▄▄▄       ▄▄▄▄    ▄▄▄       ▒█████  ▄▄▄█████▓ ██░ ██
▒██    ▒ ▒████▄    ▓█████▄ ▒████▄    ▒██▒  ██▒▓  ██▒ ▓▒▓██░ ██▒
░ ▓██▄   ▒██  ▀█▄  ▒██▒ ▄██▒██  ▀█▄  ▒██░  ██▒▒ ▓██░ ▒░▒██▀▀██░
  ▒   ██▒░██▄▄▄▄██ ▒██░█▀  ░██▄▄▄▄██ ▒██   ██░░ ▓██▓ ░ ░▓█ ░██
▒██████▒▒ ▓█   ▓██▒░▓█  ▀█▓ ▓█   ▓██▒░ ████▓▒░  ▒██▒ ░ ░▓█▒░██▓
▒ ▒▓▒ ▒ ░ ▒▒   ▓▒█░░▒▓███▀▒ ▒▒   ▓▒█░░ ▒░▒░▒░   ▒ ░░    ▒ ░░▒░▒
░ ░▒  ░ ░  ▒   ▒▒ ░▒░▒   ░   ▒   ▒▒ ░  ░ ▒ ▒░     ░     ▒ ░▒░ ░
░  ░  ░    ░   ▒    ░    ░   ░   ▒   ░ ░ ░ ▒    ░       ░  ░░ ░
      ░        ░  ░ ░            ░  ░    ░ ░            ░  ░  ░
                         ░

"""
#Print the ascii art
cprint(motd, 'red', attrs=['bold'])

#Count if there are any arguments passed to code
arguments = len(sys.argv) - 1
if arguments == 0:
    print("Usage: ./sabaoth.py http(s)://website.com, type --help for more info.")
    exit()

#Get the first argument
link=sys.argv[1]

#Verifies if there is more arguments to check and get the user agent data
if arguments >= 3:
    #if --user-agent is defined... get the data
    if "--user-agent" in sys.argv[2]:
        user_agent = sys.argv[3]
else:
    #if not, keep going
    user_agent = "none"

#Print help info, if requested
if "--help" in link or "-h" in link:
    print("Usage example: ./sabaoth.py http://website.com/xss.php?a=\n")
    print("Usage example with custom user agents: ./sabaoth.py http://website.com/xss.php?a= --user-agent \"a custom user-agent\"\n")
    print("--help or -h: Show how to use the tool!")
    print("--version or -v: Show the version of Sabaoth")
    print("--user-agent: Set the user agent")
    exit()

#Print version of code
if "--version" in link or "-v" in link:
    print("Saboath, version 1.0.0")
    exit()

#verifies if there is a url parameter to test, if not, halt the program.
if not re.findall(r'\?\w*', link):
    print("Please specify the url parameter you want to test! type --help for more info.")
    exit()

#Verifies if there is http: or https: on the request (its necessary)
if not re.findall(r'http|https', link):
    print("You need to specify the http protocol! type --help for more info.")
    exit()

#Verify if the site is reachable
print("Doing pre-check of "+link)

#If user agent is defined, start the test request with the custom user agent!
if not user_agent == "none":
    command="curl -s -o /dev/null -H User-Agent:"+user_agent+" "+link
else:
    command="curl -s -o /dev/null "+link

#Do the site test with the acquired link and see the result, if greater then 0 is bad.
check_site=system(command)
if check_site > 0:
    print("I cant reach to this site!!!")
    exit()
else:
    print("Page is reachable! Doing next pre-check...")


#If user agent is defined, do second check, if site returns something.
if not user_agent == "none":
    headers = {
        'User-Agent': user_agent
    }
    request = requests.get(link, headers=headers)
else:
    request = requests.get(link)

#If request code acquired from the second check not 200, the page is not acessible
if not (request.status_code) == 200:
    print("Could not access the page!")
    print("Http status code:",request.status_code)
    exit()
else:
    print("Http status code 200, we're good to go!")
    print("\n")


#find what url parameter is used in XSS test
parameter_finder= r"\?(?P<parameter>.*)\="
parameter_used= re.search(parameter_finder, str(link))

#Verify if the parameter syntax is correct, if not, end the code
if parameter_used:
    print("Parameter used: "+parameter_used.group('parameter'))
else:
    print("incorrect syntax, are you using the '=' after the parameter? see --help for more info.")
    exit()

#Call the payload class to get the payloads to compare
payload=Payloads().line
for i in payload:
    #Start counting time
    start = time.time()
    #Call the Xssrun class, sending the parameters
    xss=Xssrun(link,str(i),0,0,0,0,0,user_agent)
    #End counting time, with this i can count how many time the xss run
    end = time.time()
    time_run = end - start

    #After get the Xssrun class values, compare if there is a <script>,<noscript>,<textarea>,<style>,<title> tag open on the code, if do, run a custom payload.
    if xss.script_xss == 1:
        #Rerun the XSS with </script>
        start = time.time()
        xss=Xssrun(link,"</script>"+str(i),0,0,0,0,1,user_agent)
        end = time.time()
        time_run = end - start
        #After the new run with a custom payload, if found_xss is set to 1, there is a XSS
        if xss.found_xss == 1:
            xss_qtdy=xss_qtdy + 1
            print("Found xss in payload "+link+"</script>"+str(i)+"Time elapsed for test: "+str(time_run)+" seconds")

            #Print the type of xss (if found)
            if re.findall(r'^\/\"><svg onload=alert\(34305489723146875555666\)>', str(i)):
                print("XSS Type: Simple htmli")
                print("\n")
            if re.findall(r'^<svg onload=alert\(34305489723146875555666\)>', str(i)):
                print("XSS Type: inline htmli")
                print("\n")
            if re.findall(r'^\"><svg onload=alert\(34305489723146875555666\)>', str(i)):
                print("XSS Type: inblock htmli ")
                print("\n")
            if re.findall(r'\'-alert\(34305489723146875555666\)-\'', str(i)):
                print("XSS Type: js inblock htmli")
                print("\n")
            if re.findall(r'\\\'-alert\(34305489723146875555666\)//', str(i)):
                print("XSS Type: simple js injection")
                print("\n")
            continue
    if xss.noscript_xss == 1:
        #Rerun the XSS with </noscript>
        start = time.time()
        xss=Xssrun(link,"</noscript>"+str(i),0,0,0,1,0,user_agent)
        end = time.time()
        time_run = end - start
        #After the new run with a custom payload, if found_xss is set to 1, there is a XSS
        if xss.found_xss == 1:
            xss_qtdy=xss_qtdy + 1
            print("Found xss in payload "+link+"</noscript>"+str(i)+"Time elapsed for test: "+str(time_run)+" seconds")

            #Print the type of xss (if found)
            if re.findall(r'^\/\"><svg onload=alert\(34305489723146875555666\)>', str(i)):
                print("XSS Type: Simple htmli")
                print("\n")
            if re.findall(r'^<svg onload=alert\(34305489723146875555666\)>', str(i)):
                print("XSS Type: inline htmli")
                print("\n")
            if re.findall(r'^\"><svg onload=alert\(34305489723146875555666\)>', str(i)):
                print("XSS Type: inblock htmli ")
                print("\n")
            if re.findall(r'\'-alert\(34305489723146875555666\)-\'', str(i)):
                print("XSS Type: js inblock htmli")
                print("\n")
            if re.findall(r'\\\'-alert\(34305489723146875555666\)//', str(i)):
                print("XSS Type: simple js injection")
                print("\n")
            continue
    if xss.textarea_xss == 1:
        #Rerun the XSS with </textarea>
        start = time.time()
        xss=Xssrun(link,"</textarea>"+str(i),0,0,1,0,0,user_agent)
        end = time.time()
        time_run = end - start
        #After the new run with a custom payload, if found_xss is set to 1, there is a XSS
        if xss.found_xss == 1:
            xss_qtdy=xss_qtdy + 1
            print("Found xss in payload "+link+"</textarea>"+str(i)+"Time elapsed for test: "+str(time_run)+" seconds")

            #Print the type of xss (if found)
            if re.findall(r'^\/\"><svg onload=alert\(34305489723146875555666\)>', str(i)):
                print("XSS Type: Simple htmli")
                print("\n")
            if re.findall(r'^<svg onload=alert\(34305489723146875555666\)>', str(i)):
                print("XSS Type: inline htmli")
                print("\n")
            if re.findall(r'^\"><svg onload=alert\(34305489723146875555666\)>', str(i)):
                print("XSS Type: inblock htmli ")
                print("\n")
            if re.findall(r'\'-alert\(34305489723146875555666\)-\'', str(i)):
                print("XSS Type: js inblock htmli")
                print("\n")
            if re.findall(r'\\\'-alert\(34305489723146875555666\)//', str(i)):
                print("XSS Type: simple js injection")
                print("\n")
            continue
    if xss.style_xss == 1:
        #Rerun the XSS with </style>
        start = time.time()
        xss=Xssrun(link,"</style>"+str(i),0,1,0,0,0,user_agent)
        end = time.time()
        time_run = end - start
        #After the new run with a custom payload, if found_xss is set to 1, there is a XSS
        if xss.found_xss == 1:
            xss_qtdy=xss_qtdy + 1
            print("Found xss in payload "+link+"</style>"+str(i)+"Time elapsed for test: "+str(time_run)+" seconds")

            #Print the type of xss (if found)
            if re.findall(r'^\/\"><svg onload=alert\(34305489723146875555666\)>', str(i)):
                print("XSS Type: Simple htmli")
                print("\n")
            if re.findall(r'^<svg onload=alert\(34305489723146875555666\)>', str(i)):
                print("XSS Type: inline htmli")
                print("\n")
            if re.findall(r'^\"><svg onload=alert\(34305489723146875555666\)>', str(i)):
                print("XSS Type: inblock htmli ")
                print("\n")
            if re.findall(r'\'-alert\(34305489723146875555666\)-\'', str(i)):
                print("XSS Type: js inblock htmli")
                print("\n")
            if re.findall(r'\\\'-alert\(34305489723146875555666\)//', str(i)):
                print("XSS Type: simple js injection")
                print("\n")
            continue
    if xss.title_xss == 1:
        #Rerun the XSS with </title>
        start = time.time()
        xss=Xssrun(link,"</title>"+str(i),1,0,0,0,0,user_agent)
        end = time.time()
        time_run = end - start
        #After the new run with a custom payload, if found_xss is set to 1, there is a XSS
        if xss.found_xss == 1:
            xss_qtdy=xss_qtdy + 1
            print("Found xss in payload "+link+"</title>"+str(i)+"Time elapsed for test: "+str(time_run)+" seconds")

            #Print the type of xss (if found)
            if re.findall(r'^\/\"><svg onload=alert\(34305489723146875555666\)>', str(i)):
                print("XSS Type: Simple htmli")
                print("\n")
            if re.findall(r'^<svg onload=alert\(34305489723146875555666\)>', str(i)):
                print("XSS Type: inline htmli")
                print("\n")
            if re.findall(r'^\"><svg onload=alert\(34305489723146875555666\)>', str(i)):
                print("XSS Type: inblock htmli ")
                print("\n")
            if re.findall(r'\'-alert\(34305489723146875555666\)-\'', str(i)):
                print("XSS Type: js inblock htmli")
                print("\n")
            if re.findall(r'\\\'-alert\(34305489723146875555666\)//', str(i)):
                print("XSS Type: simple js injection")
                print("\n")
            continue


    #If just the  if found_xss is set to 1, if do, there is a XSS
    if xss.found_xss == 1:
        xss_qtdy=xss_qtdy + 1
        print("Found xss in payload "+link+str(i)+"Time elapsed for test: "+str(time_run)+" seconds")

        #Print the type of xss (if found)
        if re.findall(r'^\/\"><svg onload=alert\(34305489723146875555666\)>', str(i)):
            print("XSS Type: Simple htmli")
            print("\n")
        if re.findall(r'^<svg onload=alert\(34305489723146875555666\)>', str(i)):
            print("XSS Type: inline htmli")
            print("\n")
        if re.findall(r'^\"><svg onload=alert\(34305489723146875555666\)>', str(i)):
            print("XSS Type: inblock htmli")
            print("\n")
        if re.findall(r'\'-alert\(34305489723146875555666\)-\'', str(i)):
            print("XSS Type: js inblock htmli")
            print("\n")
        if re.findall(r'\\\'-alert\(34305489723146875555666\)//', str(i)):
            print("XSS Type: simple js injection")
            print("\n")

if xss_qtdy > 0:
    print("Number of xss found: " + str(xss_qtdy))
else:
    print("No XSS found")

total_end = time.time()
total_time = total_end - total_start

print("Total time elapsed: "+str(total_time)+" seconds")
