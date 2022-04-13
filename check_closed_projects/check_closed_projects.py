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
from novaclient import client as nova
from neutronclient.neutron import client as neutron
from cinderclient import client as cinder
from glanceclient.v2 import client as glance
import re
import json


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
                 ldap_id_attributes, projects_file,
                 ldap_discrepancies_file, os_discrepancies_file,
                 resources_discrepancies_file):
        ''' Initial function called when object is created '''
        self.debug_level = debug_level
        if log_file is None:
            log_file = os.path.join(self._get_home_folder(),
                                    'log',
                                    'check_closed_projects.log')
        self.log_file = log_file
        self._init_log()
        self.ldap_conn = None
        self.images = None
        self.ips = None

        self.os_source_file = os_source_file
        self.ldap_host = ldap_host
        self.ldap_port = ldap_port
        self.ldap_user = ldap_user
        self.ldap_password = ldap_password
        self.ldap_base_dn = ldap_base_dn
        self.ldap_search_filter = ldap_search_filter
        self.ldap_id_attributes = ldap_id_attributes
        self.state_attribute = ldap_state_attribute
        self.projects_file = projects_file
        self.ldap_discrepancies_file = ldap_discrepancies_file
        self.os_discrepancies_file = os_discrepancies_file
        self.resources_discrepancies_file = resources_discrepancies_file

        self.connect_ldap()
        self.get_os_projects()
        if self.projects_file is not None:
            self.get_projects_from_file()
        else:
            self.get_ldap_projects()

        self.compare_projects()

    def connect_ldap(self):
        ''' Connect to the LDAP server if there wasn't a connection'''
        if not self.ldap_conn:
            self.ldap_conn = ldap.initialize(
                f"ldaps://{self.ldap_host}:{self.ldap_port}")
            self.ldap_conn.simple_bind_s(self.ldap_user, self.ldap_password)

    def get_ldap_projects(self):
        searchScope = ldap.SCOPE_SUBTREE
        searchFilter = self.ldap_search_filter
        attributes = [*self.ldap_id_attributes, self.state_attribute]
        projects = self.ldap_conn.search_s(self.ldap_base_dn, searchScope,
                                           searchFilter, attributes)
        if len(projects) < 1:
            self._log.error(f"""Error testing the LDAP connection.
                There are no projects (filter='{searchFilter}').""")
            sys.exit(1)
        self.ldap_projects = dict()
        for project in projects:
            for id_attr in self.ldap_id_attributes:
                cn = project[1][id_attr][0].decode()
                self.ldap_projects[cn] = {}
                for key in project[1].keys():
                    self.ldap_projects[cn][key] = project[1][key][0].decode()

    def get_projects_from_file(self):
        self.ldap_projects = dict()
        with open(self.projects_file, 'r') as projects_file:
            for line in projects_file.readlines():
                project = line.strip('\n')
                if project != "":
                    self.ldap_projects.update(
                        self.get_project_from_ldap(project)
                    )

    def get_project_from_ldap(self, project):
        searchScope = ldap.SCOPE_SUBTREE
        attributes = [*self.ldap_id_attributes, self.state_attribute]
        ldap_projects = dict()
        for id_attr in self.ldap_id_attributes:
            searchFilter = f"(&({id_attr}={project})\
({self.ldap_search_filter}))"
            projects = self.ldap_conn.search_s(self.ldap_base_dn, searchScope,
                                               searchFilter, attributes)
            if len(projects) > 0:
                for proj in projects:
                    for id_attr in self.ldap_id_attributes:
                        cn = proj[1][id_attr][0].decode()
                        ldap_projects[cn] = dict()
                        for key in proj[1].keys():
                            ldap_projects[cn][key] = proj[1][key][0].decode(
                            )
        return ldap_projects

    def get_os_projects(self):
        self._os_auth()
        os_projects = self.keystone.projects.list()
        self.os_projects = []
        for project in os_projects:
            project_dict = {
                "name": project.name,
                "id": project.id,
                "enabled": project.enabled
            }
            self.os_projects.append(project_dict)

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
({key} = '{cred[key]}'): Did you load the OpenStack RC file?")
                exit(1)
        return cred

    def _os_auth(self):
        self.keystone_session = session.Session(
            auth=v3.Password(**self._get_credentials()))
        self.keystone_v3 = keystoneclient_v3.Client(
            session=self.keystone_session)
        self.keystone = keystoneclient_v3.Client(
            session=self.keystone_session)
        self.nova = nova.Client("2.1", session=self.keystone_session)
        self.neutron = neutron.Client("2.0", session=self.keystone_session)
        self.cinder = cinder.Client("3", session=self.keystone_session)
        self.glance = glance.Client("3", session=self.keystone_session)

    def compare_projects(self):
        self.compare_ldap_vs_os()
        if self.projects_file is None:
            self.compare_os_vs_ldap()
        else:
            self.os_projects = self.os_projects_not_disabled
        self.check_os_projects_resources()

    def compare_os_vs_ldap(self):
        self._log.debug(f"Comparing {len(self.os_projects)} projects \
from OpenStack with {len(self.ldap_projects)} projects from LDAP (there might \
be duplicated if you indicated several id attributes)...")
        not_closed = list()
        state = self.state_attribute
        for os_project in self.os_projects:
            if (os_project['name'] not in self.ldap_projects and
               self.projects_file is None):
                self._log.warning(f"Project '{os_project['name']}' disabled in \
OpenStack is not in LDAP")
            elif (os_project['name'] in self.ldap_projects and
                  self.ldap_projects[os_project['name']][state] != 'closed'):
                self._log.warning(f"Project '{os_project['name']}' disabled in \
Openstack is not closed in LDAP")
                not_closed.append(self.ldap_projects[os_project['name']])
            elif os_project['name'] not in self.ldap_projects:
                self._log.debug("Ignoring project...")
#             else:
#                 self._log.debug(f"Opentack Project '{os_project['name']}' \
# it's closed in LDAP ({self.ldap_projects[os_project['name']][state]}).")
        if len(not_closed) == 0:
            self._log.info('All projects are closed in LDAP.')
        else:
            with open(self.ldap_discrepancies_file, 'w') as fileh:
                fileh.write(json.dumps(not_closed, indent=2))
            self._log.warning(f"{len(not_closed)} projects are not closed in \
LDAP. Saved in '{self.ldap_discrepancies_file}'.")

    def compare_ldap_vs_os(self):
        self._log.debug("Comparing from LDAP to OpenStack...")
        not_disabled = list()
        state = self.state_attribute
        for ldap_project in self.ldap_projects:
            if self.ldap_projects[ldap_project][state] == "closed":
                for os_project in self.os_projects:
                    if (ldap_project in os_project['name'] and
                       os_project['enabled']):
                        if os_project not in not_disabled:
                            not_disabled.append(os_project)
        if len(not_disabled) == 0:
            self._log.info('All closed LDAP projects are disabled in \
OpenStack.')
        else:
            for os_project in not_disabled:
                self._log.warning(f"OpenStack project '{os_project['name']}' \
closed in LDAP is not disabled in OpenStack")
            with open(self.os_discrepancies_file, 'w') as fileh:
                fileh.write(json.dumps(not_disabled, indent=2))
            self._log.warning(f"{len(not_disabled)} projects from LDAP are not \
disabled in OpenStack. Saved in '{self.os_discrepancies_file}'.")
        self.os_projects_not_disabled = not_disabled

    def check_os_projects_resources(self):
        self._log.debug('Checking disabled projects in OpenStack for used \
resources ...')
        for os_project in self.os_projects:
            if self.projects_file is not None or not os_project['enabled']:
                self._log.debug(f"Checking project '{os_project['name']}' \
({os_project['id']})...")
                search_opts = {
                    "project_id": os_project['id'],
                    "all_tenants": True
                }
                discrepancies = {}

                self._log.debug('Checking servers...')
                servers = self._get_os_instances(search_opts=search_opts)
                if len(servers) > 0:
                    self._log.warning(f"{len(servers)} servers in disabled \
project {os_project['name']} ({os_project['id']})")
                    discrepancies['servers'] = servers

                self._log.debug('Checking volumes...')
                volumes = self._get_os_volumes(search_opts=search_opts)
                if len(volumes) > 0:
                    self._log.warning(f"{len(volumes)} volumes in disabled \
project {os_project['name']} ({os_project['id']}")
                    discrepancies['volumes'] = volumes

                self._log.debug('Checking snapshots...')
                snapshots = self._get_os_snapshots(search_opts=search_opts)
                if len(snapshots) > 0:
                    self._log.warning(f"{len(snapshots)} snapshots in disabled \
project {os_project['name']} ({os_project['id']})")
                    discrepancies['snapshots'] = snapshots

                self._log.debug('Checking images...')
                images = self._get_os_images(owner=os_project['id'])
                if len(images) > 0:
                    self._log.warning(f"{len(images)} images in disabled \
project {os_project['name']} ({os_project['id']})")
                    discrepancies['images'] = images

                self._log.debug('Checking floating IPs...')
                ips = self._get_os_floating_ip(project_id=os_project['id'])
                if len(ips) > 0:
                    self._log.warning(f"{len(ips)} IPs in disabled \
project {os_project['name']} ({os_project['id']})")
                    discrepancies['floating_ips'] = ips

                self._log.debug('Checking security groups...')
                sec_grps = self._get_os_security_groups(
                    project_id=os_project['id']
                )
                if len(sec_grps) > 1:
                    self._log.warning(f"{len(sec_grps)} security groups in disabled \
project {os_project['name']} ({os_project['id']})")
                    discrepancies['security_groups'] = sec_grps

                self._log.debug('Checking routers...')
                routers = self._get_os_routers(project_id=os_project['id'])
                if len(routers) > 0:
                    self._log.warning(f"{len(routers)} routers in disabled \
project {os_project['name']} ({os_project['id']})")
                    discrepancies['routers'] = routers

                self._log.debug('Checking networks...')
                networks = self._get_os_networks(project_id=os_project['id'])
                if len(networks) > 0:
                    self._log.warning(f"{len(networks)} networks in disabled \
project {os_project['name']} ({os_project['id']})")
                    discrepancies['networks'] = networks

                self._log.debug('Checking roles...')
                roles = self._get_os_roles(project_id=os_project['id'])
                if len(roles) > 0:
                    self._log.warning(f"{len(roles)} roles in disabled \
project {os_project['name']} ({os_project['id']}): \
{', '.join(roles)}")
                    discrepancies['roles'] = roles

                if len(discrepancies) > 0:
                    discrepancies['project_name'] = os_project['name']
                    discrepancies['project_id'] = os_project['id']
                    # self._log.debug(discrepancies)
                    filename = self.resources_discrepancies_file.replace(
                        "%p",
                        os_project['id']
                    )
                    with open(filename, 'w') as fileh:
                        fileh.write(json.dumps(discrepancies, indent=2))

    def _get_os_instances(self, search_opts={"all_tenants": True}):
        result = []
        server_list = self.nova.servers.list(detailed=True,
                                             search_opts=search_opts)
        for server in server_list:
            result.append({'name': server.name, 'id': server.id})
        return result

    def _get_os_volumes(self, search_opts={"all_tenants": True}):
        result = []
        vols_list = self.cinder.volumes.list(detailed=True,
                                             search_opts=search_opts)
        for volume in vols_list:
            result.append({'id': volume.id})
        return result

    def _get_os_snapshots(self, search_opts={"all_tenants": True}):
        result = []
        snaps_list = self.cinder.volume_snapshots.list(detailed=True,
                                                       search_opts=search_opts)
        for snap in snaps_list:
            result.append({'id': snap.id})
        return result

    def _get_os_images(self, owner=None):
        if self.images is None:
            self._log.debug('First time fetching all images, and caching them \
in memory...')
            images = self.glance.images.list()
            self.images = images
        else:
            images = self.images
        images_list = list()
        for image in images:
            if owner and image['owner'] == owner:
                images_list.append(image)
        return images_list

    def _get_os_floating_ip(self, project_id=None):
        if self.ips is None:
            self._log.debug('First time fetching all floating IPs, and caching \
them in memory...')
            all_floating_ips = self.neutron.list_floatingips()['floatingips']
            self.ips = all_floating_ips
        else:
            all_floating_ips = self.ips
        ips = list()
        for ip in all_floating_ips:
            if project_id and ip['project_id'] == project_id:
                ips.append(ip)
        return ips

    def _get_os_security_groups(self, project_id=None):
        sg_list = self.neutron.list_security_groups(
            tenant_id=project_id
        )['security_groups']
        return sg_list

    def _get_os_routers(self, project_id=None):
        routers_list = self.neutron.list_routers(
            tenant_id=project_id
        )['routers']
        return routers_list

    def _get_os_networks(self, project_id=None):
        networks_list = self.neutron.list_networks(
            tenant_id=project_id
        )['networks']
        return networks_list

    def _get_os_roles(self, project_id=None):
        roles_list = list()
        for role in self.keystone.roles.list(project=project_id):
            roles_list.append(role.name)
        return roles_list

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
            fileh = RotatingFileHandler(self.log_file, maxBytes=max_log_size)
            # create formatter
            formatter = logging.Formatter('''%(asctime)s %(name)-12s
            %(levelname)-8s %(message)s''')
            fileh.setFormatter(formatter)
            fileh.setLevel(logging.DEBUG)
            self._log.addHandler(fileh)

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
@click.option('--ldap-id-attributes', '-i', default=['cn'], multiple=True,
              help='''LDAP attribute(s) used to uniquely identify projects in
LDAP.''')
@click.option('--projects-file', '-o', required=False,
              help='''File with a list of project names as shown in LDAP."''')
@click.option('--ldap-discrepancies-file', '-e',
              default='ldap_discrepancies_file.json',
              help='''File to save the list of LDAP projects not closed but
disabled in OpenStack.''')
@click.option('--os-discrepancies-file', '-d',
              default='os_discrepancies_file.json',
              help='''File to save the list of OpenStack projects not disabled but
closed in LDAP.''')
@click.option('--resources-discrepancies-file', '-r',
              default='%p_resources_discrepancies_file.json',
              help='''Files to save the list of resources discrepancies by
project (used resources in a project closed in LDAP). Use %p to be replaced
with project id. Attention! Files will be overwritten.''')
@click_config_file.configuration_option()
def __main__(debug_level, log_file, os_source_file, ldap_host, ldap_port,
             ldap_user, ldap_password, ldap_base_dn, ldap_search_filter,
             ldap_state_attribute, ldap_id_attributes, projects_file,
             ldap_discrepancies_file, os_discrepancies_file,
             resources_discrepancies_file):
    return check_closed_projects(debug_level, log_file, os_source_file,
                                 ldap_host, ldap_port, ldap_user,
                                 ldap_password, ldap_base_dn,
                                 ldap_search_filter, ldap_state_attribute,
                                 ldap_id_attributes, projects_file,
                                 ldap_discrepancies_file,
                                 os_discrepancies_file,
                                 resources_discrepancies_file)


if __name__ == "__main__":
    __main__()
