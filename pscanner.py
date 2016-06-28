#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Parallel IP scanner with progressbar and SSL support  """

__author__ = "Marcin Kozlowski <marcinguy@gmail.com>"

import argparse

import multiprocessing

import ssl
import socket
from socket import gethostbyname, gaierror

from dns import reversename, resolver, exception
import sys

import M2Crypto
from embparpbar import ProgressPool

import re


def make_ip(v):
    is_valid = re.match(
        "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", v)
    if is_valid:
        return v
    else:
        return str(getip(v))


def scan(d):
    ip = make_ip(str(d))

    func_result = list()
    cert = 0

    if (portcomma_flag):
        for sport in portcomma:
            if (sslp == "yes"):
                s_ = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s = ssl.wrap_socket(
                    s_, ca_certs='/usr/local/lib/python2.7/dist-packages/requests/cacert.pem',
                    cert_reqs=ssl.CERT_OPTIONAL)
                s.settimeout(0.1)
                d = str(d)
                try:
                    result = s.connect_ex((ip, int(sport)))
                except Exception, e:
                    message = "Error: " + d.rstrip() + "," + getrev(d)
                    message += str(e)
                    try:
                        cert = ssl.get_server_certificate(
                            (d, sport), ssl_version=ssl.PROTOCOL_TLSv1)
                        x509 = M2Crypto.X509.load_cert_string(cert)
                        r = x509.get_subject().as_text()
                        val = r.split(",")
                        for i, j in enumerate(val):
                            if j.find("CN=") != -1:
                                val[i] = j.replace("CN=", "")
                                val[i] = val[i].strip()
                        message += "," + val[i]
                        func_result.append(message)
                    except Exception, e:
                        func_result.append(
                            d.rstrip() + "," + getrev(d) + "," + "CERT ERROR!")
                    except ssl.SSLError:
                        func_result.append(
                            d.rstrip() + "," + getrev(d) + "," + "CERT ERROR!")
                    except socket.gaierror:
                        func_result.append(d.rstrip() + "," + "SOCKET ERROR!")
                    except socket.error:
                        func_result.append(d.rstrip() + "," + "SOCKET ERROR!")
                if result:
                  func_result.append("No SSL")
                else:
                  cert = s.getpeercert()
                  if cert:
                    subject = dict(x[0] for x in cert['subject'])
                    issued_to = subject['commonName']
                    func_result.append(
                        d.rstrip() + "," + getrev(d) + "," + "CN:" + issued_to + "," + "CERT OK")
                  else:
                    subject = "None"
                    issued_to = "None"
                    func_result.append(
                        d.rstrip() + "," + getrev(d) + "," + "CN:" + issued_to + "," + "CERT OK")
            if (sslp == "no"):
                d = str(d)
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.1)
                    result = s.connect_ex((ip, int(sport)))
                    s.close()
                except Exception, e:
                    message = "Error: " + d.rstrip() + "," + getrev(d)
                    message += str(e)
                    func_result.append(message)
                if result:
                    func_result.append(d.rstrip() + "," + str(sport) + ",closed")
                else:
                    func_result.append(d.rstrip() + "," + str(sport) + ",open")

    if (portrange_flag):
        for sport in range(int(portrange[0]), int(portrange[1])+1):
            if (sslp == "yes"):
                s_ = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s = ssl.wrap_socket(
                    s_, ca_certs='/usr/local/lib/python2.7/dist-packages/requests/cacert.pem',
                    cert_reqs=ssl.CERT_OPTIONAL)
                s.settimeout(0.1)
                d = str(d)
                try:
                    result = s.connect_ex((ip, int(sport)))
                except Exception, e:
                    message = "Error: " + d.rstrip() + "," + getrev(d)
                    message += str(e)
                    func_result.append(message)
                    try:
                        cert = ssl.get_server_certificate(
                            (d, int(sport)), ssl_version=ssl.PROTOCOL_TLSv1)
                        x509 = M2Crypto.X509.load_cert_string(cert)
                        r = x509.get_subject().as_text()
                        val = r.split(",")
                        for i, j in enumerate(val):
                            if j.find("CN=") != -1:
                                val[i] = j.replace("CN=", "")
                                val[i] = val[i].strip()
                        message += "," + val[i]
                        func_result.append(message)
                    except Exception, e:
                        func_result.append(
                            d.rstrip() + "," + "," + "CERT ERROR!")
                    except ssl.SSLError:
                        func_result.append(
                            d.rstrip() + "," + "," + "CERT ERROR!")
                    except socket.gaierror:
                        func_result.append(d.rstrip() + "," + "SOCKET ERROR!")
                    except socket.error:
                        func_result.append(d.rstrip() + "," + "SOCKET ERROR!")
                if result:
                  func_result.append("No SSL")
                else:
                  cert = s.getpeercert()
                  if cert:
                    subject = dict(x[0] for x in cert['subject'])
                    issued_to = subject['commonName']
                    func_result.append(
                        d.rstrip() + "," + "," + "CN:" + issued_to + "," + "CERT OK")
                  else:
                    subject = "None"
                    issued_to = "None"
                    func_result.append(
                        d.rstrip() + "," + "," + "CN:" + issued_to + "," + "CERT OK")
            if (sslp == "no"):
                d = str(d)
                try:
                  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                  s.settimeout(0.1)
                  result = s.connect_ex((ip, int(sport)))
                  s.close()
                except Exception, e:
                  message = "Error: " + d.rstrip() + "," + getrev(d)
                  message += str(e)
                  func_result.append(message)
                if result:
                  func_result.append(d.rstrip() + "," + str(sport) + ",closed")
                else:
                  func_result.append(d.rstrip() + "," + str(sport) + ",open")


    return func_result


def getrev(ip):
    ip = make_ip(str(ip))

    try:
        rev_name = reversename.from_address(str(ip.rstrip()))
        resolverobj = resolver.Resolver()
        resolverobj.timeout = 1
        resolverobj.lifetime = 1
        reversed_dns = str(resolverobj.query(rev_name, "PTR")[0])
        reversed_dns = reversed_dns[:-1]

        if reversed_dns is None:
            return "none"
        else:
            return reversed_dns
    except resolver.NXDOMAIN:
        return "unknown"
    except resolver.Timeout:
        return "Timed out while resolving %s" % ip.rstrip()
    except Exception, e:
        message = "Error: " + ip.rstrip()
        message += str(e)
        return message


def getip(name):
    try:
        resolverobj = resolver.Resolver()
        resolverobj.timeout = 1
        resolverobj.lifetime = 1
        ip = str(resolverobj.query(name, "A")[0])
        if ip is None:
            return "none"
        else:
            return ip
    except Exception, e:
        message = "Error: " + name.rstrip()
        message += str(e)
        return message


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Port Scanner v0.99')
    parser.add_argument(
        '-i', '--input', help='Input list of IPs', required=True)
    parser.add_argument('-o', '--output', help='Output', required=True)
    parser.add_argument('-p', '--port', help='Port number(s). Range, i.e 20-1000 or comma seperated', required=True)
    parser.add_argument('-s', '--ssl', help='SSL yes|no', required=True)
    args = parser.parse_args()
    input = args.input
    output = args.output
    port = args.port
    portcomma = port.split(",")
    if (len(portcomma) > 1):
        portcomma_flag = 1
    else:
        portcomma_flag = 0
    portrange = port.split("-")
    if (len(portrange) != 1):
        portrange_flag = 1
    else:
        portrange_flag = 0
    sslp = args.ssl
    with open(input, 'rU') as f:
        lines = f.read().splitlines()
    data = lines

    # Create pool (ppool)
    ppool = ProgressPool()

    #results = ppool.map(scan, data, pbar="Scanning")
    # pprint.pprint(results)
    for line in data:
        results = scan(line)
    resfile = open(output, 'w')
    for r in results:
        resfile.write(str(r) + "\n")
