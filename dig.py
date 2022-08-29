import os
import sys
import time
import re
import dns.name
import dns.message
import dns.query
import dns.resolver
import getpass
import subprocess
from random import choice
from collections import defaultdict
from dns import reversename

mydict = defaultdict(list)
cp_ns = []
ippat = r'\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}'

def only_ip(ippat, rrdata):
    match = re.search(ippat, rrdata)
    if match:
        return match.group()


def is_valid_hostname(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]  # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


def rev(ns):
    rev_name = reversename.from_address(ns)
    n_server = str(dns.resolver.resolve(rev_name, "PTR")[0])
    return n_server


def finder(host, ns):
    global check
    additional_ns = []
    c = 1
    types = type(host)
    if "list" in str(types):
        cleaned_host = host[1:]
    else:
        cleaned_host = [host]
    for domain in cleaned_host:
        c += 1
        name_server = ns
        ndomain = dns.name.from_text(domain)
        request = dns.message.make_query(ndomain, dns.rdatatype.NS)
        if additional_ns:
            name_server = choice(additional_ns)
        response = dns.query.udp(request, name_server, timeout=10)
        cname = []
        soa = ""
        if response.additional and len(response.additional) > 1:
            additional_ns = []
            # Skip IPv6
            for item in response.additional:
                if 'IN AAAA' not in item.to_text():
                    ip_ns = only_ip(ippat, item.to_text())
                    if ip_ns:
                        additional_ns.append(only_ip(ippat, ip_ns))
            if additional_ns:
                lns = choice(additional_ns)
                if domain not in mydict.keys():
                    mydict[domain].append(lns)
        elif response.authority:
            response1 = str(response).split('\n')
            for line in response1:
                if " SOA " in line:
                    soa = "SOA " + str((line.split(" "))[4])
            for item in response.authority:
                if " NS " in str(item):
                    check = True
                else:
                    check = False
            if check:
                additional_ns = []
                ad_ns = []
                response1 = str(response).split('\n')
                for line in response1:
                    if " NS " in line:
                        ad_ns.append(line.split(" ")[-1:])
                for ip in ad_ns:
                    result = dns.resolver.resolve(*ip, 'A')
                    for val in result:
                        additional_ns.append(val.to_text())
                if additional_ns:
                    lns1 = choice(additional_ns)
                    if domain not in mydict.keys():
                        mydict[domain].append(lns1)
                if response.answer:
                    response = str(response).split('\n')
                    for line in response:
                        if " CNAME " in line:
                            cname.append((line.split(" "))[-1])
            else:
                continue
    return mydict, additional_ns, cname, soa


def main(myhost):
    rootns = ('198.41.0.4', '199.9.14.201', '192.33.4.12',
              '199.7.91.13', '192.203.230.10', '192.5.5.241',
              '192.112.36.4', '198.97.190.53', '192.36.148.17',
              '192.58.128.30', '193.0.14.129', '199.7.83.42',
              '202.12.27.33',)
    srootns = choice(rootns)
    cleaned_myhost = myhost.split('.')
    if not cleaned_myhost[-1].endswith('.'):
        cleaned_myhost.extend('.')
    # flip list into format ['.','com','amazon' ,'www' ]
    cleaned_myhost.reverse()
    if '' in cleaned_myhost:
        cleaned_myhost.remove('')
    # Split into parts in reverse for easier querying ['.','com.', 'amazon.com.', www.amazon.com.']
    i = 1
    while i < len(cleaned_myhost):
        if i == 1:
            cleaned_myhost[i] = cleaned_myhost[i] + cleaned_myhost[i - 1]
        else:
            cleaned_myhost[i] = cleaned_myhost[i] + '.' + cleaned_myhost[i - 1]
        i += 1
    mydict, additional_ns, cname, soa1 = finder(cleaned_myhost, srootns)
    return mydict, cleaned_myhost, srootns, additional_ns, cname, soa1
