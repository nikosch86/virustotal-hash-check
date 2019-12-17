#!/usr/bin/env python3
import hashlib, json, sys, os
import requests
import argparse
import coloredlogs, logging
from datetime import datetime
logger = logging.getLogger(__name__)

VT_API_KEY = os.environ['VT_API_KEY']

argparser = argparse.ArgumentParser()
argparser.add_argument("--file", "-f", help="path to file that should be hashed and checked on VT")
argparser.add_argument("--link", "-l", help="always show report link", action='store_true')
argparser.add_argument("--time", "-t", help="always show timestamps", action='store_true')
argparser.add_argument("--verbose", "-v", action='count', default=0)
args = argparser.parse_args()

levels = [logging.WARNING, logging.INFO, logging.DEBUG]
level = levels[min(len(levels)-1,args.verbose)]
coloredlogs.install(level=level)

cacheFile = os.path.expanduser("~") + '/.config/vt-hashes.json'

def write_cache(cacheDict, cacheFile):
    if not os.path.exists(os.path.dirname(cacheFile)):
        os.mkdir(os.path.dirname(cacheFile))
    with open(cacheFile, 'w') as cacheFileFD:
        json.dump(cacheDict, cacheFileFD, sort_keys=True, indent=2)

def read_cache(cacheFile):
    if os.path.exists(cacheFile):
        with open(cacheFile, 'r') as cacheFileFD:
            cacheDict = json.load(cacheFileFD)
            return cacheDict
    else:
        return {}

def hashAndFileUpload(fileName):
    if not os.path.isfile(fileName):
        logger.error("{} is not a file".format(fileName))
        sys.exit(2)
    hasher = hashlib.sha256()
    with open(fileName, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)

    fileHash = hasher.hexdigest()
    logger.info("File: {}".format(fileName))
    # VT Hash Checker
    url = 'https://www.virustotal.com/api/v3/files/'+fileHash
    hashCache = read_cache(cacheFile)
    if fileHash in hashCache:
        result = hashCache[fileHash]
    else:
        response = requests.get(url, headers={'x-apikey': VT_API_KEY})
        if response.status_code == 204 or response.status_code == 429:
            logger.critical("  ran into rate-limiting")
            response = requests.get('https://www.virustotal.com/api/v3/groups/acme', headers={'x-apikey': VT_API_KEY})
            try:
                result = response.json()
                try:
                    daily = result['data']['attributes']['quotas']['api_requests_daily']
                    hourly = result['data']['attributes']['quotas']['api_requests_hourly']
                    logger.info("    used {} of {} hourly and {} of {} daily requests".format(hourly['used'], hourly['allowed'], daily['used'], daily['allowed']))
                except:
                    logger.critical("  could not find out quota limits")
            except:
                logger.critical("something went wrong with the request")
            sys.exit(2)
        elif response.status_code == 200:
            try:  # EAFP
                result = response.json()
            except:
                logger.critical("Error: Invalid API Key")
                logger.debug("result: {} {}".format(response.status_code, response.text))
        else:
            logger.critical("response had an unexpected status code of {}".format(response.status_code))
            logger.debug("result: {} {}".format(response.status_code, response.text))

    try:
        malicious = result['data']['attributes']['last_analysis_stats']['malicious']
        suspicious = result['data']['attributes']['last_analysis_stats']['suspicious']
        undetected = result['data']['attributes']['last_analysis_stats']['undetected']
        if malicious+suspicious > 0:
            mtime = datetime.utcfromtimestamp(os.path.getmtime(fileName)).strftime('%Y-%m-%d %H:%M:%S %Z')
            logger.critical("  {} ({}) {} times classified as malicious".format(fileHash, fileName, str(malicious)))
            logger.info("  {} times classified as suspicious".format(str(suspicious)))
            if vars(args).get('time'):
                logger.critical("  File mtime: {}".format(mtime))
            else:
                logger.info("  File mtime: {}".format(mtime))
            if vars(args).get('link'):
                logger.critical("  Report Link: " + "https://www.virustotal.com/gui/file/" + fileHash + "/detection")
            else:
                logger.info("  Report Link: " + "https://www.virustotal.com/gui/file/" + fileHash + "/detection")
        else:
            logger.info("  {} times classified as undetected".format(str(undetected)))
        hashCache[fileHash] = result
        write_cache(hashCache, cacheFile)
    except Exception as Message:
        logger.info("  Hash was not found in Malware Database")
        logger.info(Message)

hashAndFileUpload(args.file)
