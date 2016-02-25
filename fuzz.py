import requests
from lxml import html
import argparse
import sys

def main():
    parser = argparse.ArgumentParser(description="Usage: fuzz [discover | test] url OPTIONS")

    parser.add_argument("--common-words", dest="common_words", metavar="FILE", help="Newline-delimited file of common " +
        "words to be used in page guessing and input guessing. Required.")

    if len(sys.argv) < 4 :
        parser.error("Received incorrect number of arguments")

    else:
        requestedAction = sys.argv[1]
        url = sys.argv[2]
        if not url.endswith("/"):
            url += '/'

        if requestedAction == "discover" :
            #Probably have the discover functionality in its own file called discover.py
            print "Running discovery on '{}'".format(url)
            session = tryAuthenticate(url)

        else :
            parser.error("Invalid action requested")

def tryAuthenticate(url):
    s = requests.Session()
    print "Trying to authenticate to DVWA with default credentials"
    loginpage = requests.get(url + "login.php");
    tree = html.fromstring(loginpage.content)
    # r = s.post(url + "login.php", data={"username": "admin", "password": "password", "Login": "Login"})
    # print r.text

if __name__ == "__main__":
    main()
