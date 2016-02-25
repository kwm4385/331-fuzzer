import requests
import argparse
import sys

parser = argparse.ArgumentParser(description="Usage: fuzz [discover | test] url OPTIONS")

parser.add_argument("--common-words", dest="common_words", metavar="FILE", help="Newline-delimited file of common " +
    "words to be used in page guessing and input guessing. Required.")

if len(sys.argv) < 4 :
    parser.error("Received incorrect number of arguments")

else:
    requestedAction = sys.argv[1]
    url = sys.argv[2]

    if requestedAction == "discover" :
        #Probably have the discover functionality in its own file called discover.py
        print "stuff"

    else :
        parser.error("Invalid action requested")
