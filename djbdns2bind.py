#!/usr/bin/env python3

import getopt
import sys, os.path
import re


class Translator:
    ''' Translates an input file in tinydns (custom) format to bind9 format.
    '''

    def __init__(self, arguments):

        # TODO: add more RR types
        self.mappings = {
            'Z': {'type': 'SOA', 'format': 'fqdn:nameserver:email:serial:refresh:retry:expire:minimum:ttl'},
            '&': {'type': 'NS', 'format': 'hostname:ip:targetHostname'},
            '@': {'type': 'MX', 'format': 'hostname:ip:targetHostname:priority'},
            '+': {'type': 'A', 'format': 'hostname:ip'},
            'C': {'type': 'CNAME', 'format': 'hostname:targetHostname'},
            #':': 'TXT',
        }

        self.rawContents = None
        self.parsedContents = {}
        self.domain = None
        self.ttl = None

        self.setupArguments(arguments)


    def setupArguments(self, arguments):
        ''' Parse script arguments.
        '''
        try:
            opts, args = getopt.getopt(arguments, "", ["help", "run", "file="])
        except getopt.GetoptError:
            self.usage()
            sys.exit(1)

        self.actions = {
            'run': False,
            'file': None,
        }

        ''' Parse script arguments
        '''
        for opt, arg in opts:
            if opt in ('-h', "--help"):
                self.usage()
                sys.exit(1)
            elif opt in ('--run'):
                self.actions['run'] = True
            elif opt in ('--file'):
                if not os.path.isfile(arg):
                    print('Invalid input file {}.'.format(arg))
                    self.usage()
                self.actions['file'] = arg

        if self.actions['file'] is not None:
            f = open(self.actions['file'], 'r')
            self.rawContents = f.read()
            f.close()

        # --run protection
        if not self.actions['run']:
            self.usage()
            sys.exit(1)


    def parse(self):
        ''' Parses raw contents to get Resource Records.
            TODO: use self.mappings format key to parse lines
        '''
        for line in self.rawContents.splitlines():
            data = line.split(':')
            if not data or data == '':
                continue

            register = data[0][:1] # first char

            if register in self.mappings.keys():
                if self.mappings[register]['type'] == 'SOA':

                    # check main domain
                    self.domain = self._getDomain(data[0][1:])
                    if self.domain is None:
                        print('SOA main domain is invalid. Check input file syntax.')
                        sys.exit(2)

                    # fqdn:nameserver:email:serial:refresh:retry:expire:minimum:ttl
                    self.parsedContents.update(
                        {
                            'SOA': {
                                'domain':self.domain,
                                'nameserver':data[1],
                                'email':data[2],
                                'serial':data[3],
                                'refresh':data[4],
                                'retry':data[5],
                                'expire':data[6],
                                'minimum':data[7],
                                'ttl':data[8],
                            }
                        }
                    )
                    # setup default ttl for zone
                    self.ttl = self.parsedContents['SOA']['ttl']
                    if not self.ttl:
                        self.ttl = 3600 # set fallback value


                elif self.mappings[register]['type'] == 'NS':
                    if self.mappings[register]['type'] not in self.parsedContents:
                        self.parsedContents.update({self.mappings[register]['type']:[]})

                    # 'hostname:ip:targetHostname'
                    self.parsedContents[self.mappings[register]['type']].append(
                        {
                            'hostname':data[0][1:],
                            'ip':data[1],
                            'targetHostname':data[2],
                        }
                    )
                elif self.mappings[register]['type'] == 'MX':
                    if self.mappings[register]['type'] not in self.parsedContents:
                        self.parsedContents.update({self.mappings[register]['type']:[]})

                    # 'hostname:ip:targetHostname:priority'
                    self.parsedContents[self.mappings[register]['type']].append(
                        {
                            'hostname':data[0][1:],
                            'ip':data[1],
                            'targetHostname':data[2],
                            'priority':data[3]
                        }
                    )
                elif self.mappings[register]['type'] == 'A':
                    if self.mappings[register]['type'] not in self.parsedContents:
                        self.parsedContents.update({self.mappings[register]['type']:[]})

                    # 'hostname:ip'
                    self.parsedContents[self.mappings[register]['type']].append(
                        {
                            'hostname':self._getHost(data[0][1:]),
                            'ip':data[1],
                        }
                    )
                elif self.mappings[register]['type'] == 'CNAME':
                    if self.mappings[register]['type'] not in self.parsedContents:
                        self.parsedContents.update({self.mappings[register]['type']:[]})

                    # 'hostname:ip'
                    self.parsedContents[self.mappings[register]['type']].append(
                        {
                            'hostname':self._getHost(data[0][1:]),
                            'targetHostname':data[1],
                        }
                    )


    def write(self):
        ''' Prints a bind formatted zone file to stdout
        '''
        print('$ORIGIN {}.'.format(self.domain))
        print('$TTL {}'.format(self.ttl))
        print('@      IN SOA {nameserver} {email} ({serial} {refresh} {retry} {expire} {ttl})'.format(**self.parsedContents['SOA']))
        for rr in self.parsedContents['NS']:
            print('\t\t\t\t\t\tIN NS {targetHostname}'.format(**rr))

        for rr in self.parsedContents['MX']:
            print('\t\t\t\t\t\tIN MX {priority} {targetHostname}'.format(**rr))

        if 'A' in self.parsedContents:
            for rr in self.parsedContents['A']:
                print('{hostname}\t\t\t\t\t\tIN A {ip}'.format(**rr))

        if 'CNAME' in self.parsedContents:
            for rr in self.parsedContents['CNAME']:
                print('{hostname}\t\t\t\t\t\tIN CNAME {targetHostname}.'.format(**rr))


    def run(self):
        self.parse()
        self.write()


    def usage(self):
        print("./djbdns2bind.py --run [--file /path/to/djbdns.zone]")


    def _getHost(self, fqdn, full=False):
        ''' Returns a hostname from a FQDN.
        '''
        match = fqdn.split('.')

        if not match:
            return None

        if full:
            host = '.'.join(match)

        last = len(match)
        if last >= 3:
            # get only subdomain
            host = '.'.join(match[0:last-2])
        else:
            # no subdomains, get all
            host = '.'.join(match)
            host = '{}.'.format(host)

        return host


    def _getDomain(self, fqdn):
        ''' Returns a domain from a FQDN.
        '''
        match = fqdn.split('.')

        if not match:
            return None

        last = len(match)
        if last >= 3:
            # get only subdomain
            host = '.'.join(match[last-2:])
        else:
            # no subdomains, get all
            host = '.'.join(match)

        return host



if __name__ == '__main__':
    translator = Translator(sys.argv[1:])
    translator.run()
    sys.exit(0)
