
import sys
import difflib
import re
import os
import csv
import socket
import time
import geoip2.database
import geoip2.errors
import gzip
import maxminddb.errors
import netaddr
import json
import requests
from datetime import datetime
from elasticsearch import Elasticsearch

from feeds import feeds

re_ipcidr=r'([0-9]{1,3}\.){3}[0-9]{1,3}(\/([1-2][0-9]|3[0-2]|[0-9]))?'

now = datetime.now()
es = Elasticsearch(hosts=['localhost:19200'])

INDEX_NAME = now.strftime("feeds-os-%Y-%m-%d-%H")
TYPE_NAME="threats"

print("creating '%s' index..." % (INDEX_NAME))
es.indices.create(index=INDEX_NAME, ignore=400)

op_dict = {
        "index": {
            "_index": INDEX_NAME,
            "_type": TYPE_NAME
        }
}

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
            body = {"timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"), "ip": ip, "source": src, "itype": itype, "description": description,
                    "url": url}
            #res.append("%s,%s,%s\n"%(ip, src, itype))
            res.append(body)
            #es.index(index=INDEX_NAME,doc_type='threats',body={"timestamp":datetime.now(),"ip":ip,"source":src,"itype":itype,"description":description,"url":url})
    return res


if __name__=="__main__":


    if not os.path.exists('cache'):
        os.makedirs('cache')

    with open('res.csv','w') as out_file:
        es.indices.put_settings(index=INDEX_NAME,
                                body='''{
                                "index": {
                                    "refresh_interval": "-1"
                                }
                            }''',
                                ignore_unavailable=True
                                )
        id=None
        for feed in feeds:
            print(feed["type"])
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

            res=ipfeed(url,feed['description'],data,feed['source'],feed['itype'])
            if len(res)==0:
                continue
            keys=res[0].keys()
            dict_writer=csv.DictWriter(out_file,keys)
            dict_writer.writerows(res)

            cnt = 0
            total_cnt = 0
            bulk_data = []
            for entry in res:
                bulk_data.append(op_dict)
                bulk_data.append(entry)
                cnt = cnt + 1
                total_cnt = total_cnt + 1
                if cnt >= 20000:
                    print('bulk %s, %s' % (total_cnt, cnt))
                    bulk_res = es.bulk(index=INDEX_NAME, body=bulk_data)
                    cnt = 0
                    bulk_data = []

            if cnt > 0:
                print('last bulk %s %s' % (total_cnt, cnt))
                bulk_res = es.bulk(index=INDEX_NAME, body=bulk_data)
                id=bulk_res['items'][0]['index']['_id']


            # s.close()
            print('done closed socket %d' % total_cnt)

        es.indices.put_settings(index=INDEX_NAME,
                                body='''{
                                "index": {
                                    "refresh_interval": "30s"
                                }
                            }''',
                                ignore_unavailable=True
                                )

        es.indices.refresh(INDEX_NAME)
        #print(es.get(index=INDEX_NAME, doc_type="threats",id=id))

