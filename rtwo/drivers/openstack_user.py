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
            'auth_url': lc_driver._ex_force_auth_url.replace('/tokens',''),
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

    def build_nova(self, username, password, project_name, *args, **kwargs):
        """
        Ocassionally you will need the 'user nova' instead of admin nova.
        This function will build a 'proper' nova given credentials.
        """
        converted_kwargs = {
            'username':username,
            'password':password,
            'tenant_name':project_name,
            'auth_url':self.nova.client.auth_url,
            'region_name':self.nova.client.region_name}
        #TODO: Update w/ kwargs..
        nova = _connect_to_nova(*args, **converted_kwargs)
        nova.client.region_name = self.nova.client.region_name
        return nova

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

    def build_security_group(self, username, password, project_name,
            protocol_list, securitygroup_name='default', rebuild=False, *args, **kwargs):
        """
        Given a working set of credentials and a list of protocols

        Find the security group and ensure each rule is 'covered' by the
        existing set of rules. If not, add a new rule to cover this case.

        rebuild: If True, delete all rules before adding rules in protocol_list
        """

        sec_group = self.find_security_group(
                username, password, project_name, securitygroup_name)

        if not sec_group:
            raise Exception("No security group named %s found for %s"
                        % (securitygroup_name, username))

        if rebuild:
            rule_ids = [rule['id'] for rule in sec_group.rules]
            self.delete_security_group_rules(
                username, password, project_name, securitygroup_name, rule_ids)


        # Add the rule, grab updated security group
        self.add_security_group_rules(
            username, password, project_name, securitygroup_name, protocol_list)

        sec_group = self.find_security_group(
                username, password, project_name, securitygroup_name)
        return sec_group

    def delete_security_group_rules(self, username, password, project_name,
            securitygroup_name, rules):
        """
        rules - a list of rules in the form:
                [rule_id1, rule_id2, rule_id3, ...]
        """
        nova = self.build_nova(username, password, project_name)
        sec_group = nova.security_groups.find(name=securitygroup_name)
        for rule_id in rules:
            nova.security_group_rules.delete(rule_id)

    def add_security_group_rules(self, username, password, project_name,
            securitygroup_name, rule_list):
        """
        rules - a list of rules in the form:
                [(protocol, from_port, to_port, [CIDR]),
                 ...]
        """
        nova = self.build_nova(username, password, project_name)
        sec_group = nova.security_groups.find(name=securitygroup_name)
        for protocol in rule_list:
            self.add_rule_to_group(nova, protocol, sec_group)

    def add_rule_to_group(self, nova, protocol, security_group):
        """
        Add a security group rule if it doesn't already exist.
        """
        if len(protocol) == 3:
            (ip_protocol, from_port, to_port) = protocol
            cidr = None
        elif len(protocol) == 4:
            (ip_protocol, from_port, to_port, cidr) = protocol
        else:
            raise Exception("Rule tuple did not match expected output:"
                            " (protocol, from_port, to_port, [CIDR])")
        
        if not self.find_rule(security_group, ip_protocol,
                          from_port, to_port):
            nova.security_group_rules.create(security_group.id,
                                             ip_protocol=ip_protocol,
                                             from_port=from_port,
                                             to_port=to_port,
                                             cidr=cidr)
        return True


    def find_security_group(self, username, password, project_name,
                            securitygroup_name):
        nova = self.build_nova(username, password, project_name)
        return nova.security_groups.find(name=securitygroup_name)


    def list_security_groups(self, username, password, project_name):
        nova = self.build_nova(username, password, project_name)
        sec_groups = nova.security_groups.list()
        return sec_groups

    def find_rule(self, security_group, ip_protocol, from_port, to_port):
        for rule in security_group.rules:
            if rule['from_port'] <= from_port\
            and rule['to_port'] >= to_port\
            and rule['ip_protocol'] == ip_protocol:
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
                account_data['project'] = project.name
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

