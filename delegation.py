import dns.rdatatype
import dns.resolver
from collections import defaultdict
from dns import reversename
from random import choice
# Import Other Functionalities
import dig


my_resolver = dns.resolver.Resolver()
g_resolver = dns.resolver.Resolver()
mydict = defaultdict(lambda: defaultdict(list))
records = [dns.rdatatype.RdataType.A, dns.rdatatype.RdataType.NS, dns.rdatatype.RdataType.SOA,
           dns.rdatatype.RdataType.CNAME]
in_ns = []
answers = []
dele_names = []


# Initialize the Script
def main(domain):
    # Calls main() function in dig.py and get the delegation flow from root server to the given domain name
    try:
        na_s, split_domain, r_ns, in_ns, cnames, soa1 = dig.main(domain)
        if len(in_ns) == 0:
            return False, False
        for ip in in_ns:
            if ip not in str(mydict[split_domain[-1]]["NS RECORDS"]):
                mydict[split_domain[-1]]["NS RECORDS"].append(rev(ip))
        if cnames:
            cname = cnames[-1]
            if cname not in str(mydict[split_domain[-1]]["CNAME RECORDS"]):
                mydict[split_domain[-1]]["CNAME RECORDS"].append(cnames)
                dele_domain = cname
                for ip in in_ns:
                    if ip not in str(mydict[split_domain[-1]]["NS RECORDS"]):
                        mydict[dele_domain]["NS RECORDS"].append(rev(ip))
        else:
            dele_domain = domain
    except Exception as e:
        print(e)
    ns = dict(na_s)
    if domain in str(ns):
        ns.popitem()
    my_resolver.nameservers = [choice(in_ns)]
    resolv = []
    resolv.append(my_resolver.nameservers)
    res = delegate(dele_domain, resolv)
    if res is False:
        noansdic, additionalns, cname5, soa5 = dig.finder(dele_domain, *my_resolver.nameservers)
        if soa5:
            mydict[dele_domain]["SOA RECORDS"].append(soa5)
            resolv.append(my_resolver.nameservers)
    # Calls delegate() function and get the delegation flow from the given domain name till finding all the records
    # Prints the delegation flow
    print("Delegation for", domain, ": \n"
                                    "\n"
                                    "Root Nameserver                      : ", rev(r_ns), "(.)", " \n"
                                                                                                  " \n"
                                                                                                 "                                     | \n"
                                                                                                 "                                     | \n"
                                                                                                 "                                     V \n"
          )
    for k, v in list(ns.items()):
        dele_names.append(k)
        if k == "com.":
            print("TLD Nameserver                       : ", '%s' % rev(str(*v)), "(%s)" % k, " \n"
                                                                                              "\n"
                                                                                              "                                     | \n"
                                                                                              "                                     | \n"
                                                                                              "                                     V \n"
                  )
        else:
            print("Authoritative Nameserver             : ", '%s' % rev(str(*v)), "(%s)" % k, " \n"
                                                                                              "\n"
                                                                                              "                                     | \n"
                                                                                              "                                     | \n"
                                                                                              "                                     V \n"
                  )
    ct = 0
    for k, v in mydict.items():
        dele_names.append(k)
        print("Authoritative Nameserver             : ", '%s' % rev(str(*resolv[ct])), "(%s)" % k, "\n"
                                                                                                   "\n"
                                                                                                   "                                        %s" % str(
            str(list([(key, *val) for key, val in v.items()])).split(", ")).replace('[', '').replace(']', '').replace(
            '(',
            '').replace(
            ')', '').replace('"', '').replace("'", "").replace(', ', '\n                                        '), "\n"

                                                                                                                    "\n"
                                                                                                                    "                                     | \n"
                                                                                                                    "                                     | \n"
                                                                                                                    "                                     V \n"
              )
        ct += 1
    return dele_names, mydict

# Converts Address(Domain Names) to IP
def add_to_ips(add):
    result = dns.resolver.resolve(add, 'A')
    for val in result:
        return val.to_text()


def call_dig(hostname, resolv):
    prev_ns, host, rns, cname_ns, cname2, soa2 = dig.main(hostname)
    my_resolver.nameservers = [choice(cname_ns)]
    if cname2:
        mydict[hostname]["CNAME RECORDS"].append(cname2)
        resolv.append(my_resolver.nameservers)
        prev_ns, host, rns, cname_ns, cname2, soa3 = call_dig(*cname2, resolv)
    else:
        mydict[hostname]
        resolv.append(my_resolver.nameservers)
    return prev_ns, host, rns, cname_ns, cname2, soa2


# Gets the delegation flow from the domain name till finding all the records recursively if a CNAME record is found
def delegate(domain, resolv):
    resolv.append(my_resolver.nameservers)
    count = 0
    for query_type in records:
        try:
            answers = my_resolver.resolve(domain, query_type)
            if "RdataType.A" in str(query_type):
                count += 1
                for rec in answers:
                    if str(rec.address) not in mydict[domain]["A RECORDS"]:
                        mydict[domain]["A RECORDS"].append(str(rec.address))
            elif "NS" in str(query_type):
                count += 1
                for rec in answers:
                    if str(rec.target) not in mydict[domain]["NS RECORDS"]:
                        mydict[domain]["NS RECORDS"].append(str(rec.target))
            elif "SOA" in str(query_type):
                count += 1
                for rec in answers:
                    if str(rec.mname) not in mydict[domain]["SOA RECORDS"]:
                        mydict[domain]["SOA RECORDS"].append(str(rec.mname))
            elif "CNAME" in str(query_type):
                count += 1
                for rec in answers:
                    if str(rec.target) not in mydict[domain]["CNAME RECORDS"]:
                        mydict[domain]["CNAME RECORDS"].append(str(rec.target))
                cname1 = str(rec.target)
                if cname1:
                    prev_ns, host, rns, cname_ns, cname2, soa4 = call_dig(cname1, resolv)
                    if cname2:
                        continue
                    else:
                        delegate(host[-1], resolv)
            else:
                if len(mydict[domain]["NS RECORDS"]) == 1:
                    mydict[domain]["NS RECORDS"] = mydict["primevideo.com"]["NS RECORDS"]
        except dns.exception.DNSException:
            continue
    if count == 0:
        return False
    else:
        return True


# Converts IP to Address(Domain Names)
def rev(ns):
    try:
        rev_name = reversename.from_address(ns)
        n_server = str(dns.resolver.resolve(rev_name, "PTR")[0])
        return n_server
    except Exception:
        return ns


main("google.com")
