"""
OpenStack CloudAdmin Libarary
    Use this library to:
    * manage users within Keystone - openstack auth
"""
import os

from keystoneclient.exceptions import NotFound, ClientException

from threepio import logger

from rtwo.drivers.common import _connect_to_keystone,\
    _connect_to_nova, find


class UserManager():
    keystone = None
    nova = None
    user = None
    password = None
    project = None

    @classmethod
    def lc_driver_init(self, lc_driver, *args, **kwargs):
        lc_driver_args = {
            'username': lc_driver.key,
            'password': lc_driver.secret,
            'tenant_name': lc_driver._ex_tenant_name,
            'auth_url': lc_driver._ex_force_auth_url,
            'region_name': lc_driver._ex_force_service_region
        }
        lc_driver_args.update(kwargs)
        manager = UserManager(*args, **lc_driver_args)
        return manager

    def __init__(self, *args, **kwargs):
        self.keystone, self.nova = self.new_connection(*args, **kwargs)

    def new_connection(self, *args, **kwargs):
        keystone = _connect_to_keystone(*args, **kwargs)
        nova = _connect_to_nova(*args, **kwargs)
        return keystone, nova

    def add_role(username, projectname, userrole, adminrole='admin'):


        logger.debug("Assign project:%s Member:%s Role:%s" %
                    (projectname, username, adminRole))

        # For security/monitoring we will add the admin to the project with a
        # special role
        admin_role = self.get_role(adminrole)
        admin_user = self.get_user(self.keystone.username)
        admin_obj = project.add_user(admin_user, adminrole)

        # raises keystoneclient.exceptions.ClientException
        self.add_project_member(projectname, self.keystone.username, adminrole)
        created_role = self.add_project_member(projectname, username, userrole)
        return created_role

    def add_protcol_to_group(self, nova, protocol, security_group):
        """
        Add a security group rule if it doesn't already exist.
        """
        (ip_protocol, from_port, to_port) = protocol
        if not self.find_rule(security_group, ip_protocol,
                          from_port, to_port):
            nova.security_group_rules.create(security_group.id,
                                             ip_protocol=ip_protocol,
                                             from_port=from_port,
                                             to_port=to_port)
        return True

    def build_security_group(self, username, password, project_name,
            protocol_list, securitygroup_name='default', *args, **kwargs):
        #TODO: this should be a connect_to_nova
        converted_kwargs = {
            'username':username,
            'password':password,
            'tenant_name':project_name,
            'auth_url':self.nova.client.auth_url,
            'region_name':self.nova.client.region_name}

        nova = _connect_to_nova(*args, **converted_kwargs)
        nova.client.region_name = self.nova.client.region_name
        sec_group = nova.security_groups.find(name=securitygroup_name)

        for protocol in protocol_list:
            self.add_protocol_to_group(nova, protocol, sec_group)
        return nova.security_groups.find(name=securitygroup_name)

    def find_rule(self, security_group, ip_protocol, from_port, to_port):
        for r in security_group.rules:
            if r['from_port'] == from_port\
            and r['to_port'] == to_port\
            and r['ip_protocol'] == ip_protocol:
                return True
        return False

    def get_usergroup(self, username):
        return self.get_project(username)

    ##ADD##
    def create_role(self, rolename):
        """
        Create a new role
        """
        return self.keystone.roles.create(name=rolename)

    def create_project(self, groupname):
        """
        Create a new project
        """
        try:
            return self.keystone_projects().create(groupname)
        except Exception, e:
            logger.exception(e)
            raise

    def add_project_member(self, groupname, username, userrole):
        """
        Adds user(name) to group(name) with role(name)

        Invalid groupname, username, rolename :
            raise keystoneclient.exceptions.NotFound
        """
        project = self.get_project(groupname)
        user = self.get_user(username)
        role = self.get_role(userrole)
        try:
            user_obj = project.add_user(user, role)
        except Exception, e:
            logger.exception(e)
            raise

    def create_user(self, username, password=None, project=None):
        """
        Create a new user
        Invalid groupname : raise keystoneclient.exceptions.NotFound

        project - The tenant/project to assign user when creating (opt)
        """
        account_data = {
            'name': username,
            'password': password,
            'email': '%s@iplantcollaborative.org' % username,
        }
        if project:
            if self.keystone_version() == 3:
                account_data['project'] = groupname
            elif self.keystone_version() == 2:
                account_data['tenant_id'] = project.id
        return self.keystone.users.create(**account_data)

    ##DELETE##
    def delete_role(self, rolename):
        """
        Retrieve,Delete the user
        Invalid username : raise keystoneclient.exceptions.NotFound
        """
        role = self.get_role(rolename)
        if role:
            role.delete()
        return True

    def delete_project(self, groupname):
        """
        Retrieve and delete the project/group matching groupname
        Returns True on success
        Invalid groupname : raise keystoneclient.exceptions.NotFound
        """
        project = self.get_project(groupname)
        if project:
            project.delete()
        return True

    def delete_all_roles(self, username, projectname):
        project = self.get_project(projectname)
        user = self.get_user(username)
        roles = user.list_roles(project)
        for role in roles:
            project.remove_user(user, role)
            
        

    def delete_project_member(self, groupname, username, adminRole=False):
        """
        Retrieves the project and user object
        Removes user of the admin/member role
        Returns True on success
        Invalid username, groupname, rolename:
            raise keystoneclient.exceptions.NotFound
        """
        project = self.get_project(groupname)
        user = self.get_user(username)
        if adminRole:
            role = self.get_role('admin')
        else:
            role = self.get_role('defaultMemberRole')
        if not project or not user:
            return True
        try:
            project.remove_user(user, role)
            return True
        except NotFound as no_role_for_user:
            logger.debug('Error - %s: User-role combination does not exist' %
                         no_role_for_user)
            return True
        except Exception, e:
            logger.exception(e)
            raise

    def delete_user(self, username):
        """
        Retrieve,Delete the user
        Invalid username : raise keystoneclient.exceptions.NotFound
        """
        user = self.get_user(username)
        if user:
            user.delete()
        return True

    def get_role(self, rolename):
        """
        Retrieve role
        Invalid rolename : raise keystoneclient.exceptions.NotFound
        """
        try:
            return find(self.keystone.roles, name=rolename)
        except NotFound:
            return None

    def get_project(self, groupname):
        """
        Retrieve project
        Invalid groupname : raise keystoneclient.exceptions.NotFound
        """
        try:
            return find(self.keystone_projects(), name=groupname)
        except NotFound:
            return None

    def get_user(self, username):
        """
        Retrieve user
        Invalid username : raise keystoneclient.exceptions.NotFound
        """
        try:
            return find(self.keystone.users, name=username)
        except NotFound:
            return None

    def list_roles(self):
        return self.keystone.roles.list()

    def list_projects(self):
        return self.keystone_projects().list()

    def keystone_projects(self):
        if self.keystone_version() == 3:
            return self.keystone.projects
        elif self.keystone_version() == 2:
            return self.keystone.tenants

    def keystone_version(self):
        if self.keystone.version == 'v3':
            return 3
        elif self.keystone.version == 'v2.0':
            return 2

    def list_users(self):
        return self.keystone.users.list()

