# 331-fuzzer

## Setup

Project requires Python 2.7 and pip installed.

First, run

```bash
$ pip install -r deps.txt
```

to install all the required dependencies for this app.

## Example Run

```bash
$ python fuzz.py discover http://127.0.0.1/dvwa/ common_words.txt --auth dvwa
```

### Output

```bash
Running discovery on 'http://127.0.0.1/dvwa/'
Trying to authenticate to DVWA with default credentials...
Found CSRF token
Successfully logged in!
====================================================================================================
Starting page crawl...
====================================================================================================
Discovered pages by crawling:
====================================================================================================
http://127.0.0.1/dvwa/vulnerabilities/brute/
http://127.0.0.1/dvwa/phpinfo.php
http://127.0.0.1/dvwa/security.php?phpids=on
http://127.0.0.1/dvwa/instructions.php?doc=copying
http://127.0.0.1/dvwa/vulnerabilities/fi/?page=include.php
http://127.0.0.1/dvwa/security.php?test=%22><script>eval(window.name)</script>
http://127.0.0.1/dvwa/vulnerabilities/xss_s/
http://127.0.0.1/dvwa/vulnerabilities/sqli/
http://127.0.0.1/dvwa/vulnerabilities/upload/
http://127.0.0.1/dvwa/setup.php
http://127.0.0.1/dvwa/vulnerabilities/captcha/
http://127.0.0.1/dvwa/vulnerabilities/exec/
http://127.0.0.1/dvwa/vulnerabilities/fi/?page=file1.php
http://127.0.0.1/dvwa/vulnerabilities/fi/?page=file3.php
http://127.0.0.1/dvwa/ids_log.php
http://127.0.0.1/dvwa/docs/DVWA_v1.3.pdf
http://127.0.0.1/dvwa/security.php
http://127.0.0.1/dvwa/
http://127.0.0.1/dvwa/about.php
http://127.0.0.1/dvwa/vulnerabilities/csrf/
http://127.0.0.1/dvwa/instructions.php?doc=PHPIDS-license
http://127.0.0.1/dvwa/security.php?phpids=off
http://127.0.0.1/dvwa/vulnerabilities/sqli_blind/
http://127.0.0.1/dvwa/vulnerabilities/fi/?page=file2.php
http://127.0.0.1/dvwa/instructions.php?doc=PDF
http://127.0.0.1/dvwa/instructions.php?doc=readme
http://127.0.0.1/dvwa/instructions.php
http://127.0.0.1/dvwa/vulnerabilities/xss_r/
http://127.0.0.1/dvwa/instructions.php?doc=changelog
http://127.0.0.1/dvwa/logout.php
====================================================================================================
Starting page guessing...
====================================================================================================
Discovered pages by guessing:
====================================================================================================
http://127.0.0.1/dvwa/security.php
http://127.0.0.1/dvwa/vulnerabilities
http://127.0.0.1/dvwa/vulnerabilities/upload
====================================================================================================
Analyzing URLs...
====================================================================================================
Found query params:
====================================================================================================
{'page': 'http://127.0.0.1/dvwa/security.php', 'param': 'phpids'}
{'page': 'http://127.0.0.1/dvwa/security.php', 'param': 'test'}
{'page': 'http://127.0.0.1/dvwa/vulnerabilities/fi/', 'param': 'page'}
{'page': 'http://127.0.0.1/dvwa/instructions.php', 'param': 'doc'}
====================================================================================================
Discovering form inputs...
====================================================================================================
Found inputs:
====================================================================================================
{'action': u'login.php', 'inputs': [u'username', u'password', u'Login', u'user_token'], 'name': None, 'method': u'post'}
====================================================================================================
Discovering cookies...
====================================================================================================
Found cookies:
====================================================================================================
{'name': 'security', 'value': 'low'}
{'name': 'PHPSESSID', 'value': 'u59ichsbb8h2d1t25lo2q2lrg7'}
====================================================================================================
```
