#!/usr/bin/env python
# encoding: utf-8

import subprocess
import sys
import os
from time import gmtime, strftime
import glob
#from ucb import interact
import traceback
from timeout import timeout
import shutil

@timeout(300)
def trySite(site, failures, currentDirectory, directoryName, certDirectory):
    print site
    try:
        subprocess.call("openssl s_client -showcerts -connect {}:443 < /dev/null | \\".format(site) +
                    "awk -v c=-1 '/-----BEGIN CERTIFICATE-----/{inc=1;c++}\n" +
                    'inc {print > ' + '("{}level"'.format(certDirectory + '/') + ' c ".crt")}\n' +
                    "/---END CERTIFICATE-----/{inc=0}'", shell=True)
    except:
        failures.write("Couldn't get certificates for " + site + '\n')
        print 'Exiting Method'
        return
    #Add check to make sure there are at least 3 certificates
    files = os.listdir(certDirectory)
    certFiles = []
    for file in files:
        if file.startswith('level') and file.endswith('.crt'):
            certFiles.append(file)
    certFiles.sort()
    if len(certFiles) == 0:
        failures.write("Unexpected error with " + site + '\n')
        return
    largestCert = certFiles[-1:][0]
    period = largestCert.find('.')
    largestLevel = int(largestCert[5:period])
    for i in range(largestLevel):
        try:
            uri = subprocess.check_output('openssl x509 -noout -text -in {}level{}.crt | grep "OCSP - URI:"'.format(certDirectory + '/', str(i)), shell=True)
            beg = uri.find('OCSP - URI:')
        except:
            failures.write("Couldn't find OCSP URI for " + site + '\n')
            interact()
            continue
        uri = uri[beg+11:].strip()
        try:
            output = subprocess.check_output('openssl ocsp -issuer {}level{}.crt -cert {}level{}.crt -url {} -resp_text -respout {}ocsp_{}_{}.der'.format(certDirectory + '/', str(i+1), certDirectory + '/', str(i), uri, directoryName + '/', site, 'level' + str(i)), shell=True)
        except:
            failures.write("Unexpected error with " + site + '\n')
            interact()
            continue
    for f in files:
        os.remove(certDirectory + '/' + f)

def main():
    sites = open(sys.argv[1], 'r').read().splitlines()
    directoryName = 'certInfo,' + strftime("%Y-%m-%d,%H:%M:%S", gmtime())
    certDirectory = 'certs_' + strftime("%Y-%m-%d,%H:%M:%S", gmtime())
    os.mkdir(directoryName)
    os.mkdir(certDirectory)
    currentDirectory = os.path.dirname(os.path.abspath(__file__))
    failures = open(directoryName + '/failures.txt', 'w')
    
    for site in sites:
        trySite(site, failures, currentDirectory, directoryName, certDirectory)
    
    csvFile = open(directoryName + '/results.csv', 'w')
    for filename in os.listdir(directoryName):
        firstUnderscore = filename.find('_')
        if firstUnderscore == -1:
            continue
        secondUnderscore = filename.find('_level')
        filenameEnd = filename.find('.der')
        domain = filename[firstUnderscore+1:secondUnderscore]
        level = filename[secondUnderscore+1:filenameEnd]
        fileSize = os.path.getsize(directoryName + '/' + filename)
        csvFile.write(domain + ',' + level + ',' + str(fileSize) + '\n')
    shutil.rmtree(certDirectory)

    """
    #Command to capture packets using tshark
    #Command to start capturing OCSP packets: sudo tshark -i en0 -f "tcp port http" -R "ocsp.responses || ocsp.Request" -V -T text
    """

if __name__ == '__main__':
    main()