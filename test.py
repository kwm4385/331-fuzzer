

import random
from logger import *                            
from SensitiveDataLeak import *   

def test(page, session, options):


  if options.random == "true" or options.random == "True":
    logger.info("random is on")
    random.shuffle(page) 

  SensitiveDataLeak = ExploitStrategy(page, session, tactfulDataLeak(), options)

  SensitiveDataLeak.execute()