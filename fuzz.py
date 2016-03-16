import requests
import argparse
import itertools
import sys
from BeautifulSoup import BeautifulSoup, SoupStrainer
from urlparse import urljoin
import urlparse

def main():
    # Arguments
    parser = argparse.ArgumentParser(description="Web Fuzzer")
    parser.add_argument("action")
    parser.add_argument("url")
    parser.add_argument("common_words", metavar="FILE", help="Newline-delimited file of common " +
        "words to be used in page guessing and input guessing. Required.")
    parser.add_argument("--auth", dest="authtype", metavar="STRING", help="Use custom authentication for supported target apps. Options are: 'dvwa'")
    parser.add_argument("--slow", dest="slow", type=int, required=False, default=500, help=" Number of milliseconds considered when a response is considered 'slow'. Default is 500 milliseconds")
    parser.add_argument("vectors", metavar="FILE", help="Newline-delimited file of common exploits to vulnerabilities. "
        + "Required.")
    parser.add_argument("--random", dest="random", metavar="STRING", help="When off, try each input to each page "
        + "systematically.  When on, choose a random page, then a random input field and test all vectors. Default: false.")
    args = parser.parse_args()

    # Start
    requestedAction = args.action
    url = args.url
    if not url.endswith("/"):
        url += '/'

    common_words = args.common_words

    if requestedAction == "discover" :
        session = requests.Session()
        runDisovery(url, session, args.authtype, common_words)
    elif requestedAction == "test":
        session = requests.Session()
        vectors = args.vectors
        random = args.random
        runTest(url, session, args.authtype, args.slow, vectors, random, common_words)
    else:
        parser.error("Invalid action requested")

def runDisovery(url, session, authtype, common_words):
    print "Running discovery on '{}'".format(url)

    # Authenticate if applicable
    tryAuthenticate(session, url, authtype)

    # Discover pages by crawling
    print '=' * 100
    print 'Starting page crawl...'
    knownpages = crawl(url, session)
    print '=' * 100
    print "Discovered pages by crawling:"
    print '=' * 100
    for p in knownpages:
        print p
    print '=' * 100

    # Discover pages by guessing using common words file
    print 'Starting page guessing...'
    guessedpages = guessPages(url, session, common_words)
    print '=' * 100
    print "Discovered pages by guessing:"
    print '=' * 100
    for p in guessedpages:
        print p
    print '=' * 100
    if len(guessedpages) > 0:
        knownpages.update(guessedpages)

    # Discover query params in urls
    print "Analyzing URLs..."
    params = set()
    for p in knownpages:
        params.update(findQueryParams(p))
    print '=' * 100
    print "Found query params:"
    print '=' * 100
    for p in params:
        print p
    print '=' * 100

    # Discover form inputs on known pages
    print "Discovering form inputs..."
    inputs = set()
    for p in knownpages:
        inputs.update(formDiscovery(p, session, authtype))
    print '=' * 100
    print "Found inputs:"
    print '=' * 100
    for i in inputs:
        print i
    print '=' * 100

    # Discover cookies on known pages
    print "Discovering cookies..."
    cookies = set()
    for p in knownpages:
        cookies.update(cookieDiscovery(p, session))
    print '=' * 100
    print "Found cookies:"
    print '=' * 100
    for c in cookies:
        print c
    print '=' * 100

def runTest(url, session, authtype, timeThreshold, vectors, random, common_words):
    print "Running test on '{}'".format(url)

    # Authenticate if applicable
    tryAuthenticate(session, url, authtype)

    # timeRequest(lambda: requests.get(url), timeThreshold)

    pages = crawl(url, session)
    for guessedPage in guessPages(url, session, common_words):
        pages.add(guessedPage)

    print "Testing form inputs for lack of sanitization..."
    print '=' * 100
    print "Found pages lacking sanitized input fields:"
    print '=' * 100
    for unsanitizedPage in lackOfSanitization(pages, session, vectors, random):
        print unsanitizedPage

# Wraps a request in a timer and prints a message if it is greater than the threshold
# Will also print a message if the status code != 200
# Example usage: reponse = timeRequest(lambda: requests.get(url), timeThreshold)
def timeRequest(req, threshold):
    request = req()
    if request.elapsed and request.elapsed.total_seconds() * 1000 > threshold:
        print '\033[93m' + "Request to {} took longer than {} ms. ({})".format(request.url, threshold, request.elapsed) + '\033[0m'

    try:
        request.raise_for_status()
    except requests.exceptions.HTTPError as e:
        print '\033[93m' + "Request returned a non-200 status code. ({})".format(e) + '\033[0m'

    return request

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

# Guess urls by combining paths made up of common words with the base URL
def guessPages(baseurl, session, common_words):
    with open(common_words) as f:
        lines = [l.replace('\n', '') for l in f.readlines()]

    extensions = [w for w in lines if w.startswith('.')]
    words = [w for w in lines if not w.startswith('.')]

    # We want to try "no extension" too
    extensions.append('')

    foundpages = []

    # Guess paths of length 1 through 5
    for i in range(1, 5):
        paths = list(map("/".join, itertools.permutations(words, i)))
        # Guess each path by itself and with each extension
        for p in paths:
            last_line_len = 0
            for ext in extensions:
                path = urljoin(baseurl, p + ext)
                out = "Guessing " + path
                spacing = " " * (last_line_len - len(out) if last_line_len > len(out) else 0)
                out += spacing + "\r"
                last_line_len = len(out)
                sys.stdout.write(out)
                sys.stdout.flush()
                r = session.get(path)
                if r.status_code == 200:
                    foundpages.append(path)
    return foundpages

# Analyze a known URL for query params
def findQueryParams(url):
    params = []
    parsed = urlparse.urlparse(url)
    query = urlparse.parse_qs(parsed.query)
    for q in query:
        params.append(str({"page": url.split("?")[0].encode('ascii','ignore'), "param": q.encode('ascii','ignore')}))
    return params

# Find forms and inputs on a page
def formDiscovery(url, session, auth):
    page = session.get(url)

    if "/dvwa/login.php" in page.url and "logout.php" not in url and auth == "dvwa":
        soup = BeautifulSoup(page.content)
        forms = []

        for piece in soup.findAll('form'):
            form = {'action':'','name':'','method':'','inputs': list()}
            if piece in soup.findAll('form'):
                form['name'] = piece.get('name')

            if piece.get('action') and piece.get('method'):
                form['action'] = piece.get('action')
                form['method'] = piece.get('method')

                for input_field in piece.findAll('input'):
                    if input_field.get('name'):
                        form['inputs'].append(input_field.get('name'))

            forms.append(str(form))
        return forms
    else:
        return []


def cookieDiscovery(url, session):
    cookies = []
    for c in session.cookies:
        cookies.append(str({"name": c.name, "value": c.value}))
    return cookies
    # TODO: Determine what page set a cookie

# Test that pages with form inputs sanitize their data
def lackOfSanitization(pages, session, vectors, random):
    unSanitizedPages = []
    specialChars = ['<', '>', '/', '\'', '"', '&', '#', '+', '-', ';', '|', '@', '=']
    pagesToCheck = []

    if random == "true":
        while len(pagesToCheck) < len(pages):
            i = random.randint()
            while i > len(pages) & i < 0:
                i = random.randint()
            if not pages[i] in pagesToCheck:
                pagesToCheck.append(pages[i])

    else:
        pagesToCheck = pages

    for page in pagesToCheck:
        url = page.get("url")
        specialCharFound = False

        while not specialCharFound:
            for vector in vectors:
                soup = BeautifulSoup(page.content)
                payload = []

                for input_field in soup.findAll("input"):
                    payload[input_field] = vector

                response = session.post(url, data=payload)
                for char in specialChars:
                    if char in response.text:
                        unSanitizedPages.append(url)
                        specialCharFound = True
                        break

    return unSanitizedPages

if __name__ == "__main__":
    main()
