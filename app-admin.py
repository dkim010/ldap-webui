#!/usr/bin/env python3

import bottle
from bottle import get, post, static_file, request, route, template
from bottle import SimpleTemplate
from configparser import ConfigParser
from ldap3 import Connection, Server
from ldap3 import SIMPLE, SUBTREE
from ldap3.core.exceptions import LDAPBindError, LDAPConstraintViolationResult, \
    LDAPInvalidCredentialsResult, LDAPUserNameIsMandatoryError, \
    LDAPSocketOpenError, LDAPExceptionError
from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups
import logging
import os
from os import environ, path


BASE_DIR = path.dirname(__file__)
LOG = logging.getLogger(__name__)
LOG_FORMAT = '%(asctime)s %(levelname)s: %(message)s'
VERSION = '2.1.0'


@route('/static/<filename>', name='static')
def serve_static(filename):
    return static_file(filename, root=path.join(BASE_DIR, 'static'))


@get('/')
def get_index():
    groups = CONF['rule']['groups']
    return index_tpl(groups=groups)


@post('/')
def post_index():
    form = request.forms.getunicode

    def error(msg):
        return index_tpl(username=form('username'),
            groups=groups,
            group=form('group'),
            email=form('email'),
            alerts=[('error', msg)])

    groups = CONF['rule']['groups']
    group_list = groups.split(',')
    if form('group') not in group_list:
        return error("group must be one of {}".format(groups))

    try:
        create_accounts(form('admin-password'), form('username'), form('email'), form('group'))
    except Error as e:
        LOG.warning("Unsuccessful attempt to create account for %s: %s" % (form('username'), e))
        return error(str(e))

    LOG.info("Account has been created successfully for: %s" % form('username'))

    default_password = CONF['rule']['default_password']
    return index_tpl(groups=groups,
        alerts=[('success', f'"{form("username")}" account has been created with default password "{default_password}"')])


def index_tpl(**kwargs):
    return template('index-admin', **kwargs)


def connect_ldap(conf, **kwargs):
    server = Server(host=conf['host'],
                    port=conf.getint('port', None),
                    use_ssl=conf.getboolean('use_ssl', False),
                    connect_timeout=5)

    return Connection(server, raise_exceptions=True, **kwargs)


def create_accounts(admin_password, username, email, group):
    changed = []
    for key in (key for key in CONF.sections()
                if key == 'ldap' or key.startswith('ldap:')):
        LOG.debug("Create account in %s for %s" % (key, username))
        try:
            create_account(CONF[key], admin_password, username, email, group)
            changed.append(key)
        except Error as e:
            for key in reversed(changed):
                LOG.info("Reverting account creation in %s for %s" % (key, username))
                try:
                    delete_account(CONF[key], admin_password, username, group, email)
                except Error as e2:
                    LOG.error('{}: {!s}'.format(e.__class__.__name__, e2))
            raise e


def create_account(conf, admin_password, username, email, group):
    try:
        _create_account(conf, admin_password, username, email, group)
    except (LDAPBindError, LDAPInvalidCredentialsResult, LDAPUserNameIsMandatoryError):
        raise Error('Admin password is incorrect!')

    except LDAPSocketOpenError as e:
        LOG.error('{}: {!s}'.format(e.__class__.__name__, e))
        raise Error('Unable to connect to the remote server.')

    except LDAPExceptionError as e:
        LOG.error('{}: {!s}'.format(e.__class__.__name__, e))
        raise Error('Encountered an unexpected error while communicating with the remote server.')


def _create_account(conf, admin_password, username, email, group):
    user = username + '@' + conf['ad_domain']
    # admin credential
    with connect_ldap(conf, authentication=SIMPLE, user=conf['admin_bind_dn'],
        password=admin_password) as c:
        c.bind()
        dn = f'CN={username},{conf["base"]}'
        attrs = {
            'cn': f'{username}',
            'name': f'{username}',
            'sAMAccountName': f'{username}',
            'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
            'userPrincipalName': f'{username}@{conf["ad_domain"]}',
            'mail': email,
        }
        LOG.info(('dn', dn))
        LOG.info(('attrs', attrs))

        # create account
        c.add(dn=dn, attributes=attrs)
        LOG.info(('create_account', c.result))

        # add to group
        group_dn = f'CN={group},{conf["base"]}'
        ad_add_members_to_groups(c, dn, group_dn)
        LOG.info(('ad_add_members_to_groups', c.result))


def modify_account(conf, username, group):
    pass


def delete_account(conf, username, new_pass, group):
    pass


def read_config():
    config = ConfigParser()
    config.read([path.join(BASE_DIR, 'settings.admin.ini'), os.getenv('CONF_FILE', '')])

    return config


class Error(Exception):
    pass


if environ.get('DEBUG'):
    bottle.debug(True)

# Set up logging.
logging.basicConfig(format=LOG_FORMAT)
LOG.setLevel(logging.INFO)
LOG.info("Starting ldap-passwd-webui %s" % VERSION)

CONF = read_config()

bottle.TEMPLATE_PATH = [BASE_DIR]

# Set default attributes to pass into templates.
SimpleTemplate.defaults = dict(CONF['html'])
SimpleTemplate.defaults['url'] = bottle.url


# Run bottle internal server when invoked directly (mainly for development).
if __name__ == '__main__':
    bottle.run(**CONF['server'])
# Run bottle in application mode (in production under uWSGI server).
else:
    application = bottle.default_app()
