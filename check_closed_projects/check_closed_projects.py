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
                 ldap_state_attribute_value,
                 ldap_id_attributes, ldap_attributes, projects_file,
                 ldap_discrepancies_file, ldap_attribute_in_openstack,
                 os_discrepancies_file, resources_discrepancies_file,
                 stop_commands_file, removal_commands_file,
                 i_want_to_generate_deletion_command):
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
        self.ldap_attributes = ldap_attributes
        self.state_attribute = ldap_state_attribute
        self.closed = ldap_state_attribute_value
        self.projects_file = projects_file
        self.ldap_discrepancies_file = ldap_discrepancies_file
        self.ldap_attribute_in_openstack = ldap_attribute_in_openstack
        self.os_discrepancies_file = os_discrepancies_file
        self.resources_discrepancies_file = resources_discrepancies_file
        self.stop_commands_file = stop_commands_file
        self.removal_commands_file = removal_commands_file
        self.generate_deletion_command = i_want_to_generate_deletion_command
        # ToDo (adelgado) Implement generation of scripts

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
        search_scope = ldap.SCOPE_SUBTREE
        search_filter = self.ldap_search_filter
        attributes = [
            *self.ldap_id_attributes,
            *self.ldap_attributes,
            self.state_attribute,
            self.ldap_attribute_in_openstack
        ]
        projects = self.ldap_conn.search_s(self.ldap_base_dn, search_scope,
                                           search_filter, attributes)
        if len(projects) < 1:
            self._log.error(f"""Error testing the LDAP connection.
                There are no projects (filter='{search_filter}').""")
            sys.exit(1)
        self.ldap_projects = dict()
        for project in projects:
            for id_attr in self.ldap_id_attributes:
                id = project[1][self.ldap_attribute_in_openstack][0].decode()
                self.ldap_projects[id] = {}
                for key in project[1].keys():
                    self.ldap_projects[id][key] = project[1][key][0].decode()

    def get_projects_from_file(self):
        self.ldap_projects = dict()
        with open(self.projects_file, 'r') as projects_file:
            lines = projects_file.readlines()
            self._log.debug(f"There are {len(lines)} projects in the file...")
            for line in lines:
                project = line.strip('\n')
                if project != "":
                    self.ldap_projects.update(
                        self.get_project_from_ldap(project)
                    )

    def get_project_from_ldap(self, project):
        search_scope = ldap.SCOPE_SUBTREE
        attributes = [
            *self.ldap_id_attributes,
            *self.ldap_attributes,
            self.state_attribute,
            self.ldap_attribute_in_openstack
        ]
        ldap_projects = dict()
        os_id = self.ldap_attribute_in_openstack
        for id_attr in self.ldap_id_attributes:
            search_filter = f"(&({id_attr}={project})\
({self.ldap_search_filter}))"
            projects = self.ldap_conn.search_s(self.ldap_base_dn,
                                               search_scope,
                                               search_filter,
                                               attributes
                                               )
            if len(projects) > 0:
                for proj in projects:
                    for id_attr in self.ldap_id_attributes:
                        id = proj[1][os_id][0].decode()
                        ldap_projects[id] = dict()
                        for key in proj[1].keys():
                            ldap_projects[id][key] = proj[1][key][0].decode(
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
        '''Compare project between LDAP and OpenStack'''
        self.report_os_discrepancies()
        if self.projects_file is None:
            self.report_ldap_discrepancies()
        else:
            self.os_projects = self.os_projects_proj_to_check
        self.check_os_projects_resources()

    def report_ldap_discrepancies(self):
        '''Report projects not closed in LDAP but disabled in OpenStack.'''
        self._log.debug(f"Comparing {len(self.os_projects)} projects \
from OpenStack with {len(self.ldap_projects)} projects from LDAP (there might \
be duplicated if you indicated several id attributes)...")
        not_closed = list()
        state = self.state_attribute
        for os_project in self.os_projects:
            if (os_project['name'] not in self.ldap_projects and
               self.projects_file is None and
               not os_project['enabled']):
                self._log.warning(f"Project '{os_project['name']}' disabled in \
OpenStack is not present in LDAP")
            elif (os_project['name'] in self.ldap_projects and
                  self.ldap_projects[os_project['name']][state] != self.closed
                  and not os_project['enabled']):
                self._log.warning(f"Project '{os_project['name']}' disabled in \
Openstack is not closed in LDAP")
                not_closed.append(self.ldap_projects[os_project['name']])
        if len(not_closed) == 0:
            self._log.info('All projects are closed in LDAP.')
        else:
            with open(self.ldap_discrepancies_file, 'w') as fileh:
                fileh.write(json.dumps(not_closed, indent=2))
            self._log.warning(f"{len(not_closed)} projects are not closed in \
LDAP. Saved in '{self.ldap_discrepancies_file}'.")

    def report_os_discrepancies(self):
        '''Report resources of projects in OpenStack that are closed in LDAP'''
        self._log.debug(f"Comparing {len(self.ldap_projects)} projects from \
LDAP with {len(self.os_projects)} from OpenStack...")
        proj_to_check = list()
        state = self.state_attribute
        ldap_projects = self.ldap_projects
        for ldap_project in ldap_projects:
            if ldap_projects[ldap_project][state].lower() == self.closed:
                for os_project in self.os_projects:
                    if ldap_project == os_project['name']:
                        if os_project not in proj_to_check:
                            project_mix = os_project
                            project_mix['ldap_info'] = ldap_projects[
                                ldap_project
                            ]
                            proj_to_check.append(project_mix)
        if len(proj_to_check) == 0:
            self._log.info('None of the LDAP closed projects are present in \
OpenStack.')
        else:
            for os_project in proj_to_check:
                self._log.debug(f"OpenStack project '{os_project['name']}' \
closed in LDAP is in OpenStack")
            with open(self.os_discrepancies_file, 'w') as fileh:
                fileh.write(json.dumps(proj_to_check, indent=2))
            self._log.warning(f"{len(proj_to_check)} \
(out of {len(self.ldap_projects)}) projects from LDAP are present in \
OpenStack. Saved in '{self.os_discrepancies_file}'.")
        self.os_projects_proj_to_check = proj_to_check

    def check_os_projects_resources(self):
        self._log.debug('Checking projects in OpenStack for used \
resources ...')
        if self.generate_deletion_command:
            commands_filename = self.removal_commands_file
            file_header = "Commands to remove resources from disabled \
OpenStack projects"
        else:
            commands_filename = self.stop_commands_file
            file_header = "Commands to stop servers and disable Openstack \
projects"
        with open(commands_filename, 'w') as commands_file:
            commands_file.write(f"# {file_header}\n")
            for os_project in self.os_projects:
                # Sanity check in case of requesting the commands to delete
                # resources, to ensure that first all projects are disabled in
                # OpenStack
                if self.generate_deletion_command and os_project['enabled']:
                    self._log.error(f"Error! The project {os_project['name']} \
from OpenStack is still enabled. Run this script without the flag to remove \
resources, to generate the commands to stop and disable the projects, review \
the commands, execute them and then try again to remove resources.")
                    exit(1)
                # If a file with a list of projects in LDAP was given
                # or the project is not enabled in OpenStack
                if self.projects_file is not None or not os_project['enabled']:
                    self._log.debug(f"Checking project '{os_project['name']}' \
({os_project['id']})...")
                    search_opts = {
                        "project_id": os_project['id'],
                        "all_tenants": True
                    }
                    discrepancies = {}
                    commands_file.write(f"# Resources in project \
{os_project['name']} ({os_project['id']})\n")

                    self._log.debug('Checking role assignments...')
                    roles = self._get_os_roles_assignments(
                        project_id=os_project['id']
                        )
                    if len(roles) > 0:
                        self._log.warning(f"{len(roles)} role assignments in \
disabled project {os_project['name']} ({os_project['id']}): \
{', '.join(roles)}")
                        discrepancies['roles'] = roles
                        if self.generate_deletion_command:
                            for role in roles:
                                commands_file.write(f"openstack role remove \
--project {os_project['id']} --group {os_project['id']} {role['id']}\n")

                    self._log.debug('Checking servers...')
                    servers = self._get_os_instances(search_opts=search_opts)
                    if len(servers) > 0:
                        self._log.warning(f"{len(servers)} servers in \
project {os_project['name']} ({os_project['id']})")
                        discrepancies['servers'] = servers
                        for server in servers:
                            if self.generate_deletion_command:
                                commands_file.write(f"openstack server delete \
{server}\n # OpenStack state '{server['OS-EXT-STS:vm_state']}'\n")
                            else:
                                commands_file.write(f"openstack server stop \
{server['id']} # OpenStack state '{server['OS-EXT-STS:vm_state']}'\n")
                                commands_file.write(f"openstack server set \
--state error {server['id']}'\n")

                    self._log.debug('Checking volumes...')
                    volumes = self._get_os_volumes(search_opts=search_opts)
                    if len(volumes) > 0:
                        self._log.warning(f"{len(volumes)} volumes in \
project {os_project['name']} ({os_project['id']}")
                        discrepancies['volumes'] = volumes
                        if self.generate_deletion_command:
                            for volume in volumes:
                                commands_file.write(f"openstack volume delete \
{volume['id']}\n")

                    self._log.debug('Checking snapshots...')
                    snapshots = self._get_os_snapshots(search_opts=search_opts)
                    if len(snapshots) > 0:
                        self._log.warning(f"{len(snapshots)} snapshots in \
project {os_project['name']} ({os_project['id']})")
                        discrepancies['snapshots'] = snapshots
                        if self.generate_deletion_command:
                            for snapshot in snapshots:
                                commands_file.write(f"openstack volume snapshot \
delete {snapshot['id']}\n")

                    self._log.debug('Checking images...')
                    images = self._get_os_images(owner=os_project['id'])
                    if len(images) > 0:
                        self._log.warning(f"{len(images)} images in \
project {os_project['name']} ({os_project['id']})")
                        discrepancies['images'] = images
                        if self.generate_deletion_command:
                            for image in images:
                                commands_file.write(f"openstack image set \
--unprotected {image['id']}\n")
                                commands_file.write(f"openstack image delete \
{image['id']}\n")

                    self._log.debug('Checking floating IPs...')
                    ips = self._get_os_floating_ip(project_id=os_project['id'])
                    if len(ips) > 0:
                        self._log.warning(f"{len(ips)} IPs in \
project {os_project['name']} ({os_project['id']})")
                        discrepancies['floating_ips'] = ips
                        if self.generate_deletion_command:
                            for ip in ips:
                                commands_file.write(f"openstack floating ip \
delete {ip['id']}\n")

                    self._log.debug('Checking security groups...')
                    sec_grps = self._get_os_security_groups(
                        project_id=os_project['id']
                    )
                    if len(sec_grps) > 1:
                        self._log.warning(f"{len(sec_grps)} security groups in \
disabled project {os_project['name']} ({os_project['id']})")
                        discrepancies['security_groups'] = sec_grps
                        if self.generate_deletion_command:
                            for group in sec_grps:
                                commands_file.write(f"openstack security group \
delete {group['id']}\n")

                    self._log.debug('Checking routers...')
                    routers = self._get_os_routers(project_id=os_project['id'])
                    if len(routers) > 0:
                        self._log.warning(f"{len(routers)} routers in \
    project {os_project['name']} ({os_project['id']})")
                        discrepancies['routers'] = routers
                        if self.generate_deletion_command:
                            for router in routers:
                                # todo (adelgado) get ports and remove them
                                # from the router
                                ports = self._get_is_router_ports(
                                    project_id={os_project['id']},
                                    router=router)
                                for port in ports:
                                    commands_file.write(f"openstack router \
remove port {router['id']} {port['id']}\n")
                                commands_file.write(f"openstack router delete \
{router['id']}\n")

                    self._log.debug('Checking networks...')
                    networks = self._get_os_networks(
                        project_id=os_project['id'])
                    if len(networks) > 0:
                        self._log.warning(f"{len(networks)} networks in \
    project {os_project['name']} ({os_project['id']})")
                        discrepancies['networks'] = networks
                        if self.generate_deletion_command:
                            for network in networks:
                                commands_file.write(f"openstack network delete \
{network['id']}\n")

                    if not self.generate_deletion_command:
                        commands_file.write(f"openstack project set --disable \
{os_project['id']}\n")
                    else:
                        commands_file.write("# curl to the API to set the \
deleted_data flag into the project in IdM/LDAP. Once the process is ready.")

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
            result.append(server.__dict__['_info'])
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

    def _get_os_roles(self):
        roles_list = list()
        for role in self.keystone.roles.list():
            roles_list.append(role.__dict__['_info'])
        return roles_list

    def _get_os_role_by_id(self, id):
        roles = self._get_os_roles()
        for role in roles:
            if role['id'] == id:
                return role

    def _get_os_roles_assignments(self, project_id=None):
        role_assignment_list = list()
        for role_a in self.keystone.role_assignments.list(project=project_id):
            role_info = role_a.__dict__['_info']
            os_role = self._get_os_role_by_id(role_info['role']['id'])
            role_assignment_list.append(os_role['name'])
        return role_assignment_list

    def _get_os_router_ports(self, project_id, router):
        if isinstance(router, dict):
            router = router['id']
        ports_list = ()
        for port in self.neutron.list_ports(project=project_id, router=router):
            ports_list.append(port)
        return ports_list

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
@click.option('--ldap-state-attribute-value', '-l', default='closed',
              help='Value for the --ldap-state-attribute that indicates that \
an LDAP project is closed.')
@click.option('--ldap-id-attributes', '-i', default=['cn'], multiple=True,
              help='''LDAP attribute(s) used to uniquely identify projects in
LDAP.''')
@click.option('--ldap-attributes', '-t', default=[], multiple=True,
              help='''LDAP attributes to fetch and to include as project
information in OpenStack in order to identify the discrepancies manually.''')
@click.option('--projects-file', '-o', required=False,
              help='''File with a list of project names as shown in LDAP."''')
@click.option('--ldap-discrepancies-file', '-e',
              default='ldap_discrepancies_file.json',
              help='''File to save the list of LDAP projects not closed but
disabled in OpenStack.''')
@click.option('--ldap-attribute-in-openstack', '-o', default='cn',
              help='''Attribute in LDAP that match the project name in \
Openstack''')
@click.option('--os-discrepancies-file', '-d',
              default='os_discrepancies_file.json',
              help='''File to save the list of OpenStack projects not disabled
but closed in LDAP.''')
@click.option('--resources-discrepancies-file', '-r',
              default='%p_resources_discrepancies_file.json',
              help='''Files to save the list of resources discrepancies by
project (used resources in a project closed in LDAP). Use %p to be replaced
with project id. Attention! Files will be overwritten.''')
@click.option('--stop-commands-file', '-c',
              default='stop_servers_disable_projects_commands.sh',
              help='File to write the commands to stop all servers and disable \
OpenStack projects that are closed in LDAP.')
@click.option('--removal-commands-file', '-x',
              default='remove_resources_commands.sh',
              help='File to write the commands to remove the resources of \
OpenStack projects that are closed in LDAP.')
@click.option('--I-want-to-generate-deletion-command', default=False,
              is_flag=True,
              help='''Attention! This would generate commands (in bash scripts) \
to delete all resources of projects if they are disabled. If a project is not \
disabled, it will stop.''')
@click_config_file.configuration_option()
def __main__(debug_level, log_file, os_source_file, ldap_host, ldap_port,
             ldap_user, ldap_password, ldap_base_dn, ldap_search_filter,
             ldap_state_attribute, ldap_state_attribute_value,
             ldap_id_attributes, ldap_attributes,
             projects_file,
             ldap_discrepancies_file, ldap_attribute_in_openstack,
             os_discrepancies_file,
             resources_discrepancies_file,
             stop_commands_file, removal_commands_file,
             i_want_to_generate_deletion_command):
    return check_closed_projects(debug_level, log_file, os_source_file,
                                 ldap_host, ldap_port, ldap_user,
                                 ldap_password, ldap_base_dn,
                                 ldap_search_filter, ldap_state_attribute,
                                 ldap_state_attribute_value,
                                 ldap_id_attributes, ldap_attributes,
                                 projects_file,
                                 ldap_discrepancies_file,
                                 ldap_attribute_in_openstack,
                                 os_discrepancies_file,
                                 resources_discrepancies_file,
                                 stop_commands_file, removal_commands_file,
                                 i_want_to_generate_deletion_command)


if __name__ == "__main__":
    __main__()
