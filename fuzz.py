import requests
import argparse
import sys
from BeautifulSoup import BeautifulSoup as bs

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
            session.get(url + "login.php")

        else :
            parser.error("Invalid action requested")

# Loads the login form for DVWA and tries to log in
def tryAuthenticate(url):
    s = requests.Session()
    print "Trying to authenticate to DVWA with default credentials..."
    try:
        requests.utils.add_dict_to_cookiejar(s.cookies, {"security": "low"})
        loginpage = s.get(url + "login.php")
        soup = bs(loginpage.content)
        token = soup.body.find('input', attrs={"type": "hidden", "name": "user_token"}).get('value').encode('ascii','ignore')
        if token:
            print "Found CSRF token"

        r = s.post(url + "login.php", data={"username": "admin", "password": "password", "Login": "Login", "user_token": token})
        print "Successfully logged in!"
    except:
        print "Authentication failed!"

    return s

if __name__ == "__main__":
    main()
