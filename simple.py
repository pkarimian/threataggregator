
import sys
import difflib
import re
import os
import csv
import socket
import time
import datetime
import geoip2.database
import geoip2.errors
import gzip
import maxminddb.errors
import netaddr
import json
import requests

from feeds import feeds

re_ipcidr=r'([0-9]{1,3}\.){3}[0-9]{1,3}(\/([1-2][0-9]|3[0-2]|[0-9]))?'

def download_file(url, filename):
    """
    :param url: URL of file to download
    :param filename: Filename to write the result object to
    :return:
    """
    r = requests.get(url, stream=True)

    with open(filename, 'wb') as fd:
        for chunk in r.iter_content(1024):
            fd.write(chunk)

def ipfeed(url, description, data, src, itype):
    """ Builds reputation DB based on one IP per line
    Only imports valid IPs

    Format is one IP per line with no further details. EG:

    1.2.3.4
    3.4.5.2
    9.9.9.9

    :param string url: URL for generic IP feed to include in DB entry
    :param string description: Description of DB entry
    :param list data: List of lines to parse
    :return: RepDB: A RepDB() instance containing threat information
    """
    res=[]
    for line in data:
        ipmatch = re.search(re_ipcidr, line)
        # if url=='https://check.torproject.org/exit-addresses':
        #     print(re.search(re_ipcidr, line))
        if ipmatch:
            ip = ipmatch.group(0)
            res.append("%s,%s,%s\n"%(ip, src, itype))
    return res


if __name__=="__main__":
    if not os.path.exists('cache'):
        os.makedirs('cache')

    with open('res.csv','w') as csv:
        for feed in feeds:
            filename= 'cache/%s.txt' % feed['type']
            url=feed['url']
            try:
                download_file(url, filename)
            except requests.ConnectionError as e:
                print('Connection interrupted while downloading: {0} - {1}'.format(url, e))
                # If there's a problem just keep going.

            except IOError:
                e = sys.exc_info()[0]
                print('Error downloading: {0} - {1}'.format(url, e))
                raise IOError('Something happened {0}'.format(e))

            if os.path.isfile(filename):
                with open(filename, 'r') as fn:
                    data = fn.read().splitlines()

            csv.writelines(ipfeed(url,feed['description'],data,feed['source'],feed['itype']))

