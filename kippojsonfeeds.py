from twisted.enterprise import adbapi
from twisted.internet import defer
from twisted.python import log
import time
import uuid
import ipaddress
import ipgetter
import json
import requests
import collections
import re

class DBLogger(dblog.DBLogger):

    def start(self, cfg):
        self.outfile = file(cfg.get('database_jsonfeeds', 'logfile'), 'a')
        #Fetch URL, certificate and verify details from config file
        #URL
        submit_url = cfg.get('database_jsonfeeds','submit_url')
        self.submit_url = re.sub(r'^"|"$', '', submit_url)
        #Certificate
        certificate = cfg.get('database_jsonfeeds','certificate')
        if certificate == True:
                self.cert = (certificate['cert'], certificate['key'])
        else:
                self.cert = False
        #Verify
        verify = cfg.get('database_jsonfeeds','verify')
        if verify == "True":
                self.verify = True
        else:
                self.verify = False
        #type
        self.type = cfg.get('database_jsonfeeds','type')
        pass
    def write(self, session, msg):
        self.outfile.write('%s [%s]: %s\r\n' % \
           (session, time.strftime('%Y-%m-%d %H:%M:%S'), msg))
        self.outfile.flush()
        pass

    def createSession(self, peerIP, peerPort, hostIP, hostPort):
        sid = uuid.uuid1().hex

        #Fetch sensor name
        sensorname = self.getSensor() or "Kippo"

        #Log entry for sensor name
        self.write(sid, 'Honeypot name: %s' %sensorname)
        self.write(sid, 'New connection: %s:%s' % (peerIP, peerPort))
        self.write(sid, 'To host: %s:%s' %(hostIP, hostPort))

        sip = ipaddress.ip_address(unicode(hostIP,"utf-8"))
        self.outfile.write('IP is %s' %sip)
        invalid = sip.is_private or sip.is_multicast or sip.is_unspecified or sip.is_reserved or sip.is_loopback or sip.is_link_local
        self.outfile.write('Invalid = %s' %invalid)
        if invalid:
                sip = ipgetter.myip()
        else:
                sip = peerIP

        dip = ipgetter.myip()
        #Validate the IP address and convert the local IP to the external IP

        src = {"ip": sip, "port":peerPort}
        dst = {"ip": dip, "port":hostPort}
        self.write(sid, 'Translated source: %s' %src)
        self.write(sid, 'Translated destination: %s' %dst)

        payload = collections.OrderedDict()
        sensor = {"type":"honeypot", "name":"kippo"}
        payload["sensor"] = sensor
        payload["src"] = src
        payload["dst"] = dst
        typeid = 1
        payload["type"] = typeid
        payload["log"] = "predefined"
        test = json.dumps(payload)
#       print json.dumps(payload)
        self.write(sid,"payload %s" %test)
        self.write(sid,"URL %s" %self.submit_url)
        self.write(sid,"verify %s" %self.verify)
        self.write(sid,"certificate %s" %self.cert)
        r = requests.post(self.submit_url, data=json.dumps(payload),verify=self.verify, cert=self.cert)
        self.write(sid,"Status %s" %r.status_code)

        return sid
        pass
