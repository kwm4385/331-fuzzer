import requests
import argparse
import itertools
import sys
from BeautifulSoup import BeautifulSoup, SoupStrainer
from urlparse import urljoin, urlparse

def main():
    # Arguments
    parser = argparse.ArgumentParser(description="Web Fuzzer")
    parser.add_argument("action")
    parser.add_argument("url")
    parser.add_argument("common_words", metavar="common_words", help="Newline-delimited file of common " +
        "words to be used in page guessing and input guessing. Required.")
    parser.add_argument("--auth", dest="authtype", metavar="STRING", help="Use custom authentication for supported target apps. Options are: 'dvwa'")
    args = parser.parse_args()

    # Start
    requestedAction = args.action
    url = args.url
    common_words = args.common_words
    if not url.endswith("/"):
        url += '/'

    if requestedAction == "discover" :
        session = requests.Session()
        runDisovery(url, session, args.authtype, common_words)

    else:
        parser.error("Invalid action requested")

def runDisovery(url, session, authtype, common_words):
    print "Running discovery on '{}'".format(url)

    # Authenticate if applicable
    tryAuthenticate(session, url, authtype)

    # Discover pages by crawling
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

    # Discover cookies on known pages
    print "Discovering cookies..."
    cookies = set()
    for p in knownpages:
        cookies.update(cookieDiscovery(p, session))
    print '=' * 100
    for c in cookies:
        print c
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

def inputDiscovery(url, session):
    formDiscovery(url, session)
    cookieDiscovery(url, session)

def formDiscovery(url, session):
    print "Discovering form parameters"
    page.session.get(url)
    
    if "http://127.0.0.1/svwa/login.php" in page.url and "logout.php" not in url and auth == "dvwa":
        page, session = cookieDiscovery(url, session)
        
        soup = BeautifulSoup(page.content)
        form = list()
        
        for piece in soup.findAll('form'):
            form={'action':'','name':'','method':'','input': list()}
            if piece in soup.findAll('form'):
                form['name'] = piece['name']
                
            if piece.has.key('action') and piece.has_key('method'):
                form['action'] = piece['action']
                form['method'] = piece['method']
                
                forms.append(form)
                
                logger.info("--form '%s' found" % (piece['action']))
                
                for input_field in piece.findall('input'):
                    if input_field.has_key('name'):
                        form['inputs'].append(input_field['name'])
                        logger.info("--input field '%s' found" % (input_field['name']))
                        
        
        return forms, session
        

def cookieDiscovery(url, session):
    page = session.get(url)
    cookies = []
    for c in session.cookies:
        cookies.append(str({"name": c.name, "value": c.value}))
    return cookies
    # TODO: Determine what page set a cookie

def linkdiscovery(page, session, auth):
    
    depthend = 150
    
    purl = urlparse(page.link)
    domain = '{uri.scheme}//{uri.netloc}'.format(uri=purl)
    iri = linksearch(page.link, domain, [], session, max_depth, 0, auth)
    
    return ur

def linksearch(link, domain, iri, session, max_depth, depth, auth):
    if depth == depthend:
        return
   
    if link not in iri:
        logger.info("New: " + link)
        iri.append(link)

    page = session.get(iri)


    if "http://127.0.0.1/dvwa/login.php" in page.link and "logout.php" not in link \
        and "dvwa/login" not in link and auth == "dvwa":
        logger.info("log dvwa")
        page, session = dvwa_relogin(session, link)

    soup = BeautifulSoup(page.content)
    links = soup.findAll('a', href=True)

    for l in links:
        hrefabsolute = urljoin(page.url, l.get('href'))

        # Only include links in our domain and not seen b4
        if hrefabsolute.startswith(domain) and href_absolute not in urls:
            linksearch(hrefabsolute, domain, iri, session, depthend, depth+1, auth)

    return l



if __name__ == "__main__":
    main()
