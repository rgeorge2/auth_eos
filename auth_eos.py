#!/usr/bin/env python
"""
A Python Script that authenticates against Kerberos using credentials from a keyring
"""

from __future__ import print_function

import keyring
import getpass
import getopt
import sys
import pexpect
import subprocess
import logging

LOG_FORMAT = "%(levelname)s: %(message)s"

REALM = "EOS.NCSU.EDU"
CELLS = ["eos.ncsu.edu", "unity.ncsu.edu"]

ARGS = "sgv"
USAGE = "Usage: auth_eos -s \t set credentials \n\
         auth_eos -g \t authenticate"


def set_credentials():
    user = raw_input("Enter username:")
    passwd = getpass.getpass("Enter password for {}@{}:".format(user, REALM))

    logging.info("Saving username")
    keyring.set_password(REALM, "username", user)
    logging.info("Saving password")
    keyring.set_password(REALM, "password", passwd)


def get_credentials():
    logging.info("Getting username")
    user = keyring.get_password(REALM, "username")
    logging.info("Getting password")
    passwd = keyring.get_password(REALM, "password")

    return user, passwd


def kinit(user_fq, passwd):
    initialize = pexpect.spawn('kinit', [user_fq])

    idx = initialize.expect(['Password for {}:'.format(user_fq), pexpect.EOF, pexpect.TIMEOUT])
    if idx == 0:
        logging.info("Received password prompt. Sending password.")
        initialize.sendline(passwd)
    else:
        logging.error("Did not receive password prompt.")
        sys.exit(-1)

    idx = initialize.expect(['kinit: Password incorrect while getting initial credentials', pexpect.EOF, pexpect.TIMEOUT])
    if idx == 0:
        logging.error("Wrong password to kinit")
        sys.exit(-1)
    elif idx == 1:
        logging.info("kinit: Success")
    else:
        logging.error("kinit: No response")

def aklog(cells):
    for cell in cells:
        logging.info("Getting token for {}".format(cell))
        subprocess.call(["aklog", "-c", cell, "-k", REALM])

def authenticate(user, passwd, cells=CELLS):
    user_fq = "{}@{}".format(user, REALM)
    logging.info("Getting ticket-granting ticket through kinit.")
    kinit(user_fq, passwd)
    logging.info("Getting tokens through aklog")
    aklog(cells)

if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], ARGS)
    except getopt.GetoptError as e:
        print(e)
        print(USAGE)
        sys.exit(2)

    pure_opts = [o for o,a in opts]

    if '-v' in pure_opts:
        logging.basicConfig(format=LOG_FORMAT, level=logging.DEBUG)
        logging.info("Enabling verbose output.")
    else:
        logging.basicConfig(format=LOG_FORMAT)


    if '-s' in pure_opts and '-g' in pure_opts:
        logging.error("Both -s and -g. Cannot set and authenticate simultaneously.")
        print(USAGE)
        sys.exit(3)
    elif '-s' in pure_opts:
        logging.info("Setting credentials to keyring")
        set_credentials()
    elif '-g' in pure_opts:
        logging.info("Getting credentials from keyring")
        creds = get_credentials()
        logging.info("Authenticating")
        authenticate(creds[0], creds[1])
    else:
        logging.error("Neither -s and -g.")
        print(USAGE)
        sys.exit(3)

    sys.exit(0)
