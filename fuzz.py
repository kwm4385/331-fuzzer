import requests
import argparse
import sys
from BeautifulSoup import BeautifulSoup, SoupStrainer
from urlparse import urljoin

def main():
    parser = argparse.ArgumentParser(description="Web Fuzzer")

    parser.add_argument("action")
    parser.add_argument("url")
    parser.add_argument("common_words", metavar="common_words", help="Newline-delimited file of common " +
        "words to be used in page guessing and input guessing. Required.")
    parser.add_argument("--auth", dest="authtype", metavar="STRING", help="Use custom authentication for supported target apps. Options are: 'dvwa'")

    args = parser.parse_args()
    print args

    requestedAction = args.action
    url = args.url
    if not url.endswith("/"):
        url += '/'

    if requestedAction == "discover" :
        session = requests.Session()
        runDisovery(session, url, args.authtype)

    else:
        parser.error("Invalid action requested")

def runDisovery(session, url, authtype):
    print "Running discovery on '{}'".format(url)
    tryAuthenticate(session, url, authtype)
    print 'Starting page crawl...'
    knownpages = crawl(url, session)
    print "\nDiscovered pages:"
    print '=' * 100
    for p in knownpages:
        print p
    print '=' * 100


# Loads the login form for DVWA and tries to log in
def tryAuthenticate(session, url, authtype):
    s = session
    if authtype == "dvwa":
        print "Trying to authenticate to DVWA with default credentials..."
        try:
            requests.utils.add_dict_to_cookiejar(s.cookies, {"security": "low"})
            loginpage = s.get(url + "login.php")
            soup = BeautifulSoup(loginpage.content)
            token = soup.body.find('input', attrs={"type": "hidden", "name": "user_token"}).get('value').encode('ascii','ignore')
            if token:
                print "Found CSRF token"

            r = s.post(url + "login.php", data={"username": "admin", "password": "password", "Login": "Login", "user_token": token})
            print "Successfully logged in!"
        except Exception as e:
            print "Authentication failed! " + str(e)

        return s

# Starting with the root url, follows all links recursively and compiles a list of all known pages
def crawl(baseurl, session, url="", knownpages=set()):
    newurl = url if url != "" else baseurl
    if newurl.endswith('.pdf'):
        return set()

    # print "Crawling " + newurl
    root = session.get(newurl)
    soup = BeautifulSoup(root.content, parseOnlyThese=SoupStrainer('a'))
    newpages = []
    for link in soup:
        if link.get('href') and not link.get('href').startswith("http"):
            newpages += [urljoin(newurl, link.get('href'))]

    if len(set(newpages) - knownpages) == 0:
        return knownpages
    else:
        deeper = []
        for url in set(newpages) - set(knownpages):
            knownpages.update([url])
            deeper += crawl(baseurl, session, url, knownpages)
        res = set()
        for s in deeper:
            res.update([s])
        return res

def inputDiscovery(url, session):
    formDiscovery(url, session)
    cookieDiscovery(url, session)

def formDiscovery(url, session):
    print "Discovering form parameters"

def cookieDiscovery(url, session):
    page = session.get(url)
    print "Discovering cookies"

    for discovered_cookie in session.cookies:
        cookie = {"name": discovered_cookie.name, "value": discovered_cookie.value}
        print cookie

if __name__ == "__main__":
    main()
