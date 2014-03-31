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

REALM = "EOS.NCSU.EDU"
CELLS = ["eos.ncsu.edu", "unity.ncsu.edu"]

ARGS = "sgv"
USAGE = "Usage: auth_eos -s \t set credentials \n\
         auth_eos -g \t authenticate"


def set_credentials():
    user = raw_input("Enter username:")
    passwd = getpass.getpass("Enter password for {}@{}:".format(user, REALM))

    keyring.set_password(REALM, "username", user)
    keyring.set_password(REALM, "password", passwd)


def get_credentials():
    user = keyring.get_password(REALM, "username")
    passwd = keyring.get_password(REALM, "password")

    return user, passwd


def kinit(user_fq, passwd):
    initialize = pexpect.spawn('kinit', [user_fq])
    idx = initialize.expect(['Password for {}:'.format(user_fq), pexpect.EOF, pexpect.TIMEOUT])
    if idx == 0:
        initialize.sendline(passwd)
    else:
        sys.exit(-1)

def aklog(cells):
    for cell in cells:
        subprocess.call(["aklog", "-c", cell, "-k", REALM])

def authenticate(user, passwd, cells=CELLS):
    user_fq = "{}@{}".format(user, REALM)
    kinit(user_fq, passwd)
    aklog(cells)

if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], ARGS)
    except getopt.GetoptError as e:
        print(e)
        print(USAGE)
        sys.exit(2)

    pure_opts = [o for o,a in opts]

    if '-s' in pure_opts and '-g' in pure_opts:
        print(USAGE)
        sys.exit(3)
    elif '-s' in pure_opts:
        set_credentials()
    elif '-g' in pure_opts:
        creds = get_credentials()
        authenticate(creds[0], creds[1])
    else:
        print(USAGE)
        sys.exit(3)

    sys.exit(0)
