"""



"""
import sys 										
import requests										
import ppropint
from logger import *
from custom_auth import *							
from options import *								
from discovery.discover import * 					
from fuzzing.test import *							

prop = ppropint.propettypropinter(indent=4)

(options, args) = parser.parse_args()

logger.info(options)

if len(sys.argv) < 4:
	parser.error("Please enter correct number of arguments")

else:
	steps = sys.argv[1]
	url = sys.argv[2]

	if steps == "discover" or steps == "test":
		page = None
		session = None

		
		if options.common_words is None:
			parser.error("newline-delimited file of common words is required for discovery. Please run python fuzz.py --help for usage.")

		elif options.vectors is None and steps == "test":
			parser.error("newline-delimited file of vectors is required for fuzzing/testing. Please run python fuzz.py --help for usage.")

		elif options.sensitive is None and steps == "test":
			parser.error("newline-delimited file of sensitive data is required for fuzzing/testing. Please run python fuzz.py --help for usage.")
			
		else:

			
			# site authentic were needed
			if options.app_to_auth is not None:

				try:
					username = custom_auth[options.app_to_auth.lower()]["username"]
					password = custom_auth[options.app_to_auth.lower()]["password"]
				except:
					parser.error("application specified in --custom-auth does not exist!")

				if options.app_to_auth.lower() == "dvwa":

					
					getauth = {
						"username": username,
						"password": password,
						"Login": "Login"
					}

					session = requests.Session()
					session.post(custom_auth[options.app_to_auth.lower()]["login_url"], data=getauth)
					page = session.get(url + "/" + options.app_to_auth)

					
					cookies = session.cookies
					session_id = cookies["PHPSESSID"]
					session.cookies.clear()

					session.cookies["PHPSESSID"] = session_id
					session.cookies["security"] = "low"
					
				elif options.app_to_auth.lower() == "bodgeit":

					
					session = requests.Session()
					page = session.get(custom_auth[options.app_to_auth.lower()]["login_url"])

			
			else:
				session = requests.Session()
				page = session.get(url)

			
			if page.status_code != 200:
				parser.error("can't reach")
			else:
				logger.info("Successfully reached page!")


		
			discovered_urls, session = page_discovery(page, session, options.common_words, options.app_to_auth)
			discovered_pages = list()
			
			for url in discovered_urls:
				inputs, session = input_discovery(url,session, options.app_to_auth)
				discovered_page = { 'url': url, 'inputs': inputs }
				discovered_pages.append(discovered_page)

			

			if steps == "test":
				test_pages(discovered_pages, session, options)
	else:

		parser.error("invalid steps")
