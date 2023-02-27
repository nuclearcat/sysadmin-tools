#!/usr/bin/env python3
import ipaddress
import sys
import asyncio

ASN_IPS = "asn.db"
ASN_TXT = "asn.txt"

# load subnets from txt file
# might be subnet/mask or ip , then optional comments after space (ignored)
# ip need to be validated, if not correct skip line
# also sort subnets, by ip, so we can search faster
def load_subnets(filename):
    subnets = []
    # Load subnets from txt file
    with open(filename, "r") as f:
        for line in f:
            # Remove comments after space or tab(s)
            line = line.split(" ", 1)[0]
            line = line.split("\t", 1)[0]
            # Remove newline
            line = line.rstrip("\n")
            # Verify ip address or subnet is valid
            try:
                ipaddress.ip_network(line)
            except ValueError:
                print("Invalid ip address or subnet: {}".format(line))
                continue
            subnets.append(line)

    # sort subnets for faster search
    subnets.sort(key=lambda ip: ipaddress.ip_address(ip.split("/")[0]))

    return subnets


# Load subnets from txt file and check for conflicts
def conflict_check(filename):
    # Check for conflicts
    subnets = load_subnets(filename)
    for subnet in subnets:
        for subnet2 in subnets:
            if subnet != subnet2:
                if ipaddress.ip_network(subnet).overlaps(ipaddress.ip_network(subnet2)):
                    print("Conflict found between {} and {}".format(subnet, subnet2))
    print("No conflicts found")
    sys.exit(0)


def load_asn_db():
    # Load asn.db
    asndb = {}
    with open(ASN_IPS, "r") as f:
        for line in f:
            line = line.split("\t", 1)
            # if space not present skip line
            if len(line) < 2:
                continue
            # validate if entry is ip or subnet
            try:
                ipaddress.ip_network(line[0])
            except ValueError:
                # print("Invalid ip address or subnet: {}".format(line[0]))
                continue
            asndb[line[0]] = line[1].rstrip("\n")

    return asndb


def load_asn_txt():
    # Load asn.txt
    asntxt = {}
    with open(ASN_TXT, "r") as f:
        for line in f:
            line = line.split(" ", 1)
            asntxt[line[0]] = line[1].rstrip("\n")

    return asntxt


# make async function so we dont wait it to finish
# that will check if ip is in asndb and asntxt description exist
# def asn_search(asndb, asntxt, ip):
async def asn_search(asndb, asntxt, ip):
    for subnet in asndb:
        if ipaddress.ip_address(ip) in ipaddress.ip_network(subnet):
            # print ip, asn and description
            if asndb[subnet] in asntxt:
                print(
                    "ip: {} asn: {} description: {}".format(
                        ip, asndb[subnet], asntxt[asndb[subnet]]
                    )
                )
                return
            return
    print("No ASN found for ip {}".format(ip))


# load /etc/asn.db where each line is in format: ip asn
# load /etc/asn.txt where each line is in format: asn description
# verify if ip given as argument to function is matching one of entries in asn.db
# print asn and description if found
def asn_lookup(ip):
    asndb = load_asn_db()
    asntxt = load_asn_txt()

    # Verify ip address is valid
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print("Invalid ip address: {}".format(ip))
        sys.exit(1)

    # asn_search(asndb, asntxt, ip)
    # async asn_search
    loop = asyncio.get_event_loop()
    loop.run_until_complete(asn_search(asndb, asntxt, ip))
    loop.close()

    sys.exit(1)


# asn_lookup for bulk ips stored in txt file (might have arguments or comments after space or tab, ignore them)
# also it might be subnet/mask or ip, if it is subnet, verify first and last ip in subnet
def asn_lookup_bulk(filename):
    asndb = load_asn_db()
    asntxt = load_asn_txt()

    # Load ips from txt file
    ips = []
    with open(filename, "r") as f:
        for line in f:
            # Remove comments after space or tab(s)
            line = line.split(" ", 1)[0]
            line = line.split("\t", 1)[0]
            # Remove newline
            line = line.rstrip("\n")
            # normalize subnet to ip
            if "/" in line:
                # validate if subnet is valid (e.g. no host bit set)
                try:
                    ipaddress.ip_network(line)
                    line = str(ipaddress.ip_network(line).network_address)
                except ValueError:
                    print("Invalid subnet: {}".format(line))
                    continue
            # Verify ip address is valid
            try:
                ipaddress.ip_address(line)
            except ValueError:
                print("Invalid ip address: {}".format(line))
                continue
            ips.append(line)

    # Check if ip is in asn.db, it might be inside subnet
    # assume asndb is sorted
    # run it on multiple cores
    # asn_search(asndb, asntxt, ip)
    # async asn_search
    loop = asyncio.get_event_loop()
    tasks = [asn_search(asndb, asntxt, ip) for ip in ips]
    loop.run_until_complete(asyncio.wait(tasks))
    loop.close()


def main():
    # Verify correct number of arguments
    if len(sys.argv) < 2:
        print("invalid number of arguments")
        print(
            "usage: {} <--conflict-check|--get-asn|--get-asn-bulk> <filename>".format(
                sys.argv[0]
            )
        )
        sys.exit(1)

    # if first argument is --conflict-check, check for conflicts file specified as second argument
    if sys.argv[1] == "--conflict-check":
        conflict_check(sys.argv[2])

    # if first argument is --get-asn, check for asn of ip specified as second argument
    elif sys.argv[1] == "--get-asn":
        asn_lookup(sys.argv[2])

    # if first argument is --get-asn-bulk, check for asn of ips stored in file specified as second argument
    elif sys.argv[1] == "--get-asn-bulk":
        asn_lookup_bulk(sys.argv[2])


if __name__ == "__main__":
    main()
