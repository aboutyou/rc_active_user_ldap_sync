#!/usr/bin/env python3

"""RocketChat LDAP sync for activating/deactivating users"""

# Copyright:
#   2019 M3philis <github.com/m3philis>
#   2019 P. H. <github.com/perfide>
# License:
#   BSD-2-Clause (BSD 2-Clause "Simplified" License)
#   https://spdx.org/licenses/BSD-2-Clause.html

# included
import logging
import os
import re
import sys

# 3rd-party
import ldap3  # pip3 install ldap3 / sudo apt-get install python3-ldap3
from rocketchat_API import rocketchat  # pip3 install rocketchat_API


try:
    LDAP_PASSWORD = os.environ['LDAP_PASSWORD']
    LDAP_SEARCH_BASE = os.environ['LDAP_SEARCH_BASE']
    LDAP_SERVER = os.environ['LDAP_SERVER']
    LDAP_USER = os.environ['LDAP_USER']
    RC_PASSWORD = os.environ['RC_PASSWORD']
    RC_SERVER = os.environ['RC_SERVER']
    RC_USER = os.environ['RC_USER']
except KeyError as e:
    print("ENV variable {} is not set!".format(e))
    sys.exit(3)


LOG = logging.getLogger('rc-ldap-user-state-sync')
LOG.setLevel(logging.DEBUG)
LOG_HANDLER = logging.StreamHandler()
LOG_HANDLER.setLevel(logging.DEBUG)
LOG.addHandler(LOG_HANDLER)


def get_ldap_user_cns(conn, search_base):
    """Search LDAP for inetOrgPerson objects
    Args:
        conn (ldap3.core.connection.Connection): a connected LDAP object
        search_base (str): base-dn to be used for the search
    Returns:
        set: user-CNs
    """
    ldap_user_cns = set()
    LOG.info('searching for inetOrgPerson')
    search_result = conn.search(
        search_base=search_base,
        search_filter='(objectclass=inetOrgPerson)',
        search_scope=ldap3.SUBTREE,
        attributes=[])
    if not search_result:
        LOG.error('user-search failed')
        return ldap_user_cns
    LOG.info('search-results: {}'.format(len(conn.response)))
    for entry in conn.response:
        ldap_user_cns.add(re.split('\=|,', entry['dn'].lower())[1])
    return ldap_user_cns
# end def get_user_cns


def get_rc_entries(rocket):
    """Search RocketChat users with LDAP login
    Args:
        rocket (rocketchat_API.rocketchat.RocketChat): a connected RocketChat object
    Returns:
        dict: usernames
    """
    rc_entries = dict()
    rc_total_entries = rocket.users_list().json()['total']

    for page in range(int(rc_total_entries/100)+1):
        for user in rocket.users_list(count=100, offset=page*100).json()['users']:
            try:
                if user['ldap']:
                    rc_entries[user['username'].lower()] = dict()
                    rc_entries[user['username'].lower()]['state'] = user['active']
                    rc_entries[user['username'].lower()]['userID'] = user['userID']
            except KeyError:
                LOG.debug("Local user: {}".format(user['username']))

    return rc_entries
# end def get_rc_entries


def sync_rc_state_with_ldap(ldap_user_cns, rc_user_entries):
    """Sync state from LDAP to RocketChat
    Args:
        ldap_user_cns (set): user CNs from LDAP
        rc_user_entries (dict): user and state from RocketChat
    Returns:
        dict: updated state for users
    """
    rc_user_entries_updated = dict()

    for user in rc_user_entries:
        if user in ldap_user_cns:
            if rc_user_entries[user]['state']:
                continue
            else:
                rc_user_entries_updated[user] = rc_user_entries[user]
                rc_user_entries_updated[user]['state'] = True
        else:
            if not rc_user_entries[user]['state']:
                continue
            else:
                rc_user_entries_updated[user] = rc_user_entries[user]
                rc_user_entries_updated[user]['state'] = False

    return rc_user_entries_updated
# end def sync_rc_state_with_ldap


def set_rc_state(rc_user_entries_updated, rocket):
    """Set new state for user in RocketChat
    Args:
        rc_user_entries_updated (dict): user and state for RocketChat
        rocket (rocketchat_API.rocketchat.RocketChat): a connected RocketChat object
    Returns:
        none
    """
    LOG.info("Updated user: {}".format(len(rc_user_entries_updated)))
    for user, state in rc_user_entries_updated.items():
        LOG.debug("User: {}, State: {}".format(user, state['state']))
        rocket.user_update(uder_id=user['userID'], active=user['state'])


def main():
    server = ldap3.Server(
        LDAP_SERVER,
        get_info=ldap3.ALL)
    conn = ldap3.Connection(
        server,
        user=LDAP_USER,
        password=LDAP_PASSWORD,
        auto_bind=False,
        receive_timeout=2)

    # try ldap connection with TLS
    try:
        start_tls_result = conn.start_tls()
    except ldap3.core.exceptions.LDAPSocketOpenError as e:
        LOG.error('failed to open socket: {}'.format(e))
        return 1
    except ldap3.core.exceptions.LDAPStartTLSError as e:
        # wrap socket error: _ssl.c:835: The handshake operation timed out
        LOG.error('failed to start TLS: {}'.format(e))
        return 1
    except ldap3.core.exceptions.LDAPSocketReceiveError as e:
        # error receiving data: timed out
        LOG.error('timeout while connecting: {}'.format(e))
        return 1
    assert start_tls_result is True
    LOG.debug('start_tls succeeded')
    bind_result = conn.bind()
    if not bind_result:
        LOG.error('bind failed')
        return 2
    LOG.debug('bind succeeded')

    rocket = rocketchat.RocketChat(RC_USER, RC_PASSWORD, server_url=RC_SERVER)

    ldap_user_cns = get_ldap_user_cns(conn, LDAP_SEARCH_BASE)
    rc_user_entries = get_rc_entries(rocket)
    rc_user_entries_updated = sync_rc_state_with_ldap(
        ldap_user_cns,
        rc_user_entries)
    set_rc_state(rc_user_entries_updated, rocket)


main()
