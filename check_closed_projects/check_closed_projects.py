#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
#
# This script is licensed under GNU GPL version 2.0 or above
# (c) 2022 Antonio J. Delgado
# Check closed projects in LDAP and compare with Openstack

import sys
import os
import logging
import click
import click_config_file
from logging.handlers import SysLogHandler, RotatingFileHandler
import functools
import ldap
from keystoneauth1 import session
from keystoneauth1.identity import v3
from keystoneclient.v3 import client as keystoneclient_v3
import re


def cached_property(name):
    """
    Function to cache in a dictionary some data.
    Use it as a decorator for your function and it will create a property with
    the cached data.
    """
    def decorator(func):
        @property
        @functools.wraps(func)
        def wrapper(self):
            if name not in self.__dict__:
                self.__dict__[name] = func(self)
            return self.__dict__[name]
        return wrapper
    return decorator


class CustomFormatter(logging.Formatter):
    """Logging colored formatter, adapted from
    https://stackoverflow.com/a/56944256/3638629"""

    grey = '\x1b[38;21m'
    blue = '\x1b[38;5;39m'
    yellow = '\x1b[38;5;226m'
    red = '\x1b[38;5;196m'
    bold_red = '\x1b[31;1m'
    reset = '\x1b[0m'

    def __init__(self, fmt):
        super().__init__()
        self.fmt = fmt
        self.FORMATS = {
            logging.DEBUG: self.grey + self.fmt + self.reset,
            logging.INFO: self.blue + self.fmt + self.reset,
            logging.WARNING: self.yellow + self.fmt + self.reset,
            logging.ERROR: self.red + self.fmt + self.reset,
            logging.CRITICAL: self.bold_red + self.fmt + self.reset
        }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


class check_closed_projects:

    def __init__(self, debug_level, log_file, os_source_file, ldap_host,
                 ldap_port, ldap_user, ldap_password, ldap_base_dn,
                 ldap_search_filter, ldap_state_attribute,
                 projects_file):
        ''' Initial function called when object is created '''
        self.debug_level = debug_level
        if log_file is None:
            log_file = os.path.join(self._get_home_folder(),
                                    'log',
                                    'check_closed_projects.log')
        self.log_file = log_file
        self._init_log()
        self.ldap_conn = None

        self.os_source_file = os_source_file
        self.ldap_host = ldap_host
        self.ldap_port = ldap_port
        self.ldap_user = ldap_user
        self.ldap_password = ldap_password
        self.ldap_base_dn = ldap_base_dn
        self.ldap_search_filter = ldap_search_filter
        self.state_attribute = ldap_state_attribute
        self.projects_file = projects_file

        self.connect_ldap()
        self.get_projects_from_ldap()
        # for project in self.projects_from_ldap:
        #     self._log.info(f"Project '{project[1]['cn']}'")
        if self.projects_file is not None:
            self.get_projects_from_file()
        else:
            self.get_projects_from_os()
        self.compare_projects()

    def connect_ldap(self):
        ''' Connect to the LDAP server if there wasn't a connection'''
        if not self.ldap_conn:
            self.ldap_conn = ldap.initialize(
                f"ldaps://{self.ldap_host}:{self.ldap_port}")
            self.ldap_conn.simple_bind_s(self.ldap_user, self.ldap_password)

    def get_projects_from_ldap(self):
        searchScope = ldap.SCOPE_SUBTREE
        searchFilter = self.ldap_search_filter
        attributes = ['cn', self.state_attribute]
        projects = self.ldap_conn.search_s(self.ldap_base_dn, searchScope,
                                           searchFilter, attributes)
        if len(projects) < 1:
            self._log.error(f"""Error testing the LDAP connection.
                There are no projects (filter='{searchFilter}').""")
            sys.exit(1)
        self.projects_from_ldap = {}
        for project in projects:
            cn = project[1]['cn'][0].decode()
            self.projects_from_ldap[cn] = {}
            for key in project[1].keys():
                self.projects_from_ldap[cn][key] = project[1][key][0].decode()

    def get_projects_from_file(self):
        self.projects_from_os = []
        with open(self.projects_file, 'r') as projects_file:
            for line in projects_file.readlines():
                self.projects_from_os.append(line.strip('\n'))

    def get_projects_from_os(self):
        self._os_auth()
        os_projects = self.keystone.projects.list()
        self.projects_from_os = []
        for project in os_projects:
            if not project.enabled:
                self.projects_from_os.append(project.name)

    def _get_credentials(self):
        """
        Load login information from file (if given) or environment
        :returns: credentials
        :rtype: dict
        """
        cred = dict()
        if self.os_source_file is not None:
            with open(self.os_source_file, 'r') as source_file:
                for line in source_file.readlines():
                    line = line.strip('\n')
                    line = re.sub('#.*$', '', line)
                    match = re.match(r'^export ', line)
                    if match:
                        line = re.sub('^export ', '', line)
                        variable, value = line.split('=')
                        os.environ[variable] = value
        cred['auth_url'] = os.environ.get('OS_AUTH_URL',
                                          '').replace("v2.0",
                                                      "v3")
        cred['username'] = os.environ.get('OS_USERNAME', '')
        cred['password'] = os.environ.get('OS_PASSWORD', '')
        cred['project_id'] = os.environ.get('OS_PROJECT_ID',
                                            os.environ.get('OS_TENANT_ID',
                                                           ''))
        cred['user_domain_name'] = os.environ.get('OS_USER_DOMAIN_NAME',
                                                  'default')
        for key in cred:
            if cred[key] == '':
                self._log.critical(f"Credentials not loaded into environment \
({key} = '{cred[key]}'): Did you load the RC file?")
                exit(1)
        return cred

    def _os_auth(self):
        self.keystone_session = session.Session(
            auth=v3.Password(**self._get_credentials()))
        self.keystone_v3 = keystoneclient_v3.Client(
            session=self.keystone_session)
        self.keystone = keystoneclient_v3.Client(
            session=self.keystone_session)

    def compare_projects(self):
        self._log.debug(f"Comparing {len(self.projects_from_os)} projects \
from OpenStack with {len(self.projects_from_ldap)} projects from LDAP...")
        not_closed = 0
        state = self.state_attribute
        for project in self.projects_from_os:
            if project not in self.projects_from_ldap:
                self._log.warning(f"Project '{project}' closed in OpenStack \
is not in LDAP")
            elif self.projects_from_ldap[project][state] != 'closed':
                self._log.warning(f"Project '{project}' closed in Openstack \
is not closed in LDAP")
                not_closed += 1
        if not_closed == 0:
            self._log.info('All projects are closed in LDAP.')
        else:
            self._log.info(f"{not_closed} projects are not closed in LDAP.")

    def _get_home_folder(self):
        home_folder = os.getcwd()
        if 'USERPROFILE' in os.environ:
            home_folder = os.environ['USERPROFILE']
        elif 'HOME' in os.environ:
            home_folder = os.environ['HOME']
        return home_folder

    def _init_log(self):
        ''' Initialize log object '''
        self._log = logging.getLogger("check_closed_projects")
        self._log.setLevel(logging.DEBUG)

        if not self._log.hasHandlers():

            sysloghandler = SysLogHandler()
            sysloghandler.setLevel(logging.DEBUG)
            self._log.addHandler(sysloghandler)

            streamhandler = logging.StreamHandler(sys.stdout)
            streamhandler.setLevel(logging.getLevelName(self.debug_level))
            # formatter = '%(asctime)s | %(levelname)8s | %(message)s'
            formatter = '[%(levelname)s] %(message)s'
            streamhandler.setFormatter(CustomFormatter(formatter))
            self._log.addHandler(streamhandler)

            if not os.path.exists(os.path.dirname(self.log_file)):
                os.mkdir(os.path.dirname(self.log_file))

            max_log_size = 102400000
            filehandler = RotatingFileHandler(self.log_file,
                                              maxBytes=max_log_size)
            # create formatter
            formatter = logging.Formatter('''%(asctime)s %(name)-12s
            %(levelname)-8s %(message)s''')
            filehandler.setFormatter(formatter)
            filehandler.setLevel(logging.DEBUG)
            self._log.addHandler(filehandler)

        return True


@click.command()
@click.option("--debug-level", "-d", default="INFO",
              type=click.Choice(["CRITICAL",
                                "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"],
                                case_sensitive=False,),
              help='Set the debug level for the standard output.')
@click.option('--log-file', '-l', help="File to store all debug messages.")
# @click.option("--dummy","-n", is_flag=True,
#               help="Don't do anything, just show what would be done.")
# Don't forget to add dummy to parameters of main function
@click.option('--os-source-file', '-s', required=False,
              help='''Source file from OpenStack with credentials. If not
provided environmental variables will be checked.''')
@click.option('--ldap-host', '-h', required=True,
              help='LDAP server hostname or IP.')
@click.option('--ldap-port', '-p', required=False, default=636,
              help='LDAP server port.')
@click.option('--ldap-user', '-u', required=False,
              help='LDAP user.')
@click.option('--ldap-password', '-P', required=False,
              help='''Warning! Avoid passing the password in the command line
and use a configuration file for this LDAP user password.''')
@click.option('--ldap-base-dn', '-d', required=True,
              help='LDAP base DN.')
@click.option('--ldap-search-filter', '-f', default='objectClass=Project',
              help='LDAP search filter to use.')
@click.option('--ldap-state-attribute', '-a', default='state',
              help='LDAP attribute that indicate the closed state.')
@click.option('--projects-file', '-o', required=False,
              help='''File with a list of project names as shown in LDAP."''')
@click_config_file.configuration_option()
def __main__(debug_level, log_file, os_source_file, ldap_host, ldap_port,
             ldap_user, ldap_password, ldap_base_dn, ldap_search_filter,
             ldap_state_attribute, projects_file):
    return check_closed_projects(debug_level, log_file, os_source_file,
                                 ldap_host, ldap_port, ldap_user,
                                 ldap_password, ldap_base_dn,
                                 ldap_search_filter, ldap_state_attribute,
                                 projects_file)


if __name__ == "__main__":
    __main__()
