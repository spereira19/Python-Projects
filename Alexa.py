__author__ = 'Sherryl Ann Pereira'

import dns.resolver
import csv
import cStringIO
import time
import zipfile
from urllib import urlopen

#Provide the link to the zipfile containing the Top Alexa domains
ALEXA_URL = 'http://s3.amazonaws.com/alexa-static/top-1m.csv.zip'
Latency_values = []
csvdata = []


def alexa_domain():

    f = urlopen(ALEXA_URL)
    buf = cStringIO.StringIO(f.read())
    zfile = zipfile.ZipFile(buf)
    buf = cStringIO.StringIO(zfile.read('top-1m.csv'))

    #Create the csv file and the header
    c = csv.writer(open("testfile.csv","wb"))
    c.writerow(["DomainName","NameServer","IPAddress","Latency1","Latency2","Latency3","Latency4","Latency5","Average Latency"])

    #Determine the domain name
    for line in buf:
        (rank, domain) = line.split(',')
        yield (int(rank), domain.strip())
        domain = domain.strip()
        try:
            csvdata.append(domain)
            answers = dns.resolver.query(domain,'NS')
    # If we get an answer, it's open
            count = 0
            print "NameServers for %s:" % domain
            for server in answers:
                count +=1
                if(count!=1):
                    del csvdata[:]
                    csvdata.append(domain)
                print server
                csvdata.append(server)
                for i in range(5): latency(server,i)
                print("The sum of the latencies is", sum(Latency_values))
                average = sum(Latency_values)/len(Latency_values)
                print("The average is", sum(Latency_values)/len(Latency_values))
                csvdata.append(average)
                c.writerow(csvdata)
    # NoAnswer: Contacted a server but didn't get a valid response
    # No Name servers: Couldn't get a valid answer from any of the name servers
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            print 'closed'
    # No response
        except dns.resolver.Timeout:
            pass
        del csvdata[:]
        print "\n\n"

def latency(server,i):
    #Computation of Latency
    start_timer = time.time()
    address1 = dns.resolver.query(str(server),'A')
    end_timer = time.time()
    #Calculate the latency for query to retreive name server for domain names
    latency = end_timer - start_timer   
    Latency_values.append(latency)
    for rdata in address1:
        if(i==0):
            csvdata.append(rdata)
            print(rdata)
    csvdata.append(latency)
    print latency

def top_list(num):
    a = alexa_domain()
    return [a.next() for i in range(num)]

if __name__ == "__main__":
    dns.resolver.nameserver = ['127.0.0.1']
    top_list(10)
