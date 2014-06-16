"""
OpenStack CloudAdmin Libarary
    Use this library to:
    * manage users within Keystone - openstack auth
"""
import os

from keystoneclient.exceptions import NotFound, ClientException
from novaclient.exceptions import OverLimit
from novaclient.exceptions import NotFound as NovaNotFound

from threepio import logger

from rtwo.drivers.common import _connect_to_keystone,\
    _connect_to_swift, _connect_to_nova, find


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
        self.keystone, self.nova, self.swift = self.new_connection(*args, **kwargs)

    def new_connection(self, *args, **kwargs):
        keystone = _connect_to_keystone(*args, **kwargs)
        nova = _connect_to_nova(*args, **kwargs)
        swift_args = self._get_swift_args(*args, **kwargs)
        swift = _connect_to_swift(*args, **swift_args)
        return keystone, nova, swift

    def _get_swift_args(self, *args, **kwargs):
        swift_args = {}
        swift_args['authurl'] = kwargs.get('auth_url')
        swift_args['user'] = kwargs.get('username')
        swift_args['key'] = kwargs.get('password')
        swift_args['tenant_name'] = kwargs.get('tenant_name')
        if "v2" in kwargs.get("auth_url"):
            swift_args['auth_version'] = 2
        swift_args['os_options'] = {"region_name":kwargs.get("region_name")}
        return swift_args


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

    def include_admin(self, projectname, admin_rolename='admin'):
        """
        This should be called each time an account is created:
          This gives the admin tenant access to view the users resources
          This is REQUIRED for:
          * Monitoring of instances
          * Ops
        """
        admin_role_created = self.add_project_membership(
                projectname, self.keystone.username, admin_rolename)
        return admin_role_created

    def build_security_group(self, username, password, project_name,
             security_group_name, protocol_list, rebuild=False, *args, **kwargs):
        """
        Given a working set of credentials and a list of protocols/rules
          Protocol/Rule: ("TCP/UDP/ICMP", from_port, to_port[, CIDR_to_allow])

        Retrieve existing security group and ensure each rule is created if it
        doesnt already exist.

        rebuild: If True, delete all rules before adding rules in protocol_list
        """
        sec_group = self.find_security_group(
                username, password, project_name, security_group_name)

        if not sec_group:
            raise Exception("No security group named %s found for %s"
                        % (security_group_name, username))

        if rebuild:
            rule_ids = [rule['id'] for rule in sec_group.rules]
            self.delete_security_group_rules(
                username, password, project_name, security_group_name, rule_ids)


        # Add the rule, grab updated security group
        self.add_security_group_rules(
            username, password, project_name, security_group_name, protocol_list)

        #Show the new security group (with added rules)
        sec_group = self.find_security_group(
                username, password, project_name, security_group_name)
        return sec_group

    def delete_security_group_rules(self, username, password, project_name,
            security_group_name, rules):
        """
        rules - a list of rules in the form:
                [rule_id1, rule_id2, rule_id3, ...]
        """
        sec_group = self.find_security_group(username, password,
                                             project_name, security_group_name)
        nova = self.build_nova(username, password, project_name)
        for rule_id in rules:
            nova.security_group_rules.delete(rule_id)

    def add_security_group_rules(self, username, password, project_name,
            security_group_name, rule_list):
        """
        rules - a list of rules in the form:
                [(protocol, from_port, to_port, [CIDR]),
                 ...]
        """
        sec_group = self.find_security_group(username, password,
                                             project_name, security_group_name)
        if not sec_group:
            raise Exception("Could not find security group %s for project %s"
                            % (security_group_name, project_name))
        nova = self.build_nova(username, password, project_name)
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
            try:
                nova.security_group_rules.create(security_group.id,
                                                 ip_protocol=ip_protocol,
                                                 from_port=from_port,
                                                 to_port=to_port,
                                                 cidr=cidr)
            except OverLimit, ole:
                if 'Security group rule already exists' in ole.message:
                    return True
                logger.exception(ole.__dict__)
                raise
        return True


    def find_security_group(self, username, password, project_name,
                            security_group_name):
        nova = self.build_nova(username, password, project_name)
        try:
            sec_group = nova.security_groups.find(description=security_group_name)
            return sec_group
        except NovaNotFound:
            sec_group = nova.security_groups.list()
        if sec_group:
            return sec_group[0]
        else:
            raise Exception("Could not find any security groups for user %s"
                            % username)


    def list_security_groups(self, username, password, project_name):
        nova = self.build_nova(username, password, project_name)
        sec_groups = nova.security_groups.list()
        return sec_groups

    def find_rule(self, security_group, ip_protocol,
                  from_port, to_port, cidr=None):
        ip_protocol = ip_protocol.lower()
        for rule in security_group.rules:
            if rule['ip_protocol'] and rule['ip_protocol'].lower() == ip_protocol\
                    and (not cidr or rule['ip_range']['cidr'] == cidr):
                #Potential match
                if rule['from_port'] <= from_port\
                        and rule['to_port'] >= to_port:
                    return True
                if rule['from_port'] == None\
                        and rule['to_port'] >= to_port:
                            # The ICMP rule on grizzly-openstack is:
                            # {'from_port': -1, ...} but on havana it is:
                            # {'from_port': None, ...} so check for both
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

    def add_project_membership(self, groupname, username, rolename):
        """
        Adds user(name) to group(name) with role(name)

        Invalid groupname, username, rolename :
            raise keystoneclient.exceptions.NotFound
        """
        # Check for previous entry
        existing_role = self.check_membership(groupname, username, rolename)
        if existing_role:
            return existing_role
        # Create a new entry
        try:
            project = self.get_project(groupname)
            user = self.get_user(username)
            new_role = self.get_role(rolename)
            user_obj = project.add_user(user, new_role)
            return new_role
        except Exception, e:
            logger.exception(e)
            raise

    def check_membership(self, projectname, username, rolename):
        user = self.get_user(username)
        project = self.get_project(projectname)
        if not user or not project:
            return None
        new_role = self.get_role(rolename)
        # Check for previous entry
        existing_roles = user.list_roles(project)
        for role in existing_roles:
            if role.name == rolename:
                return role
        return None

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

    def get_project_by_id(self, project_id):
        """
        Retrieve project
        Invalid groupname : raise keystoneclient.exceptions.NotFound
        """
        try:
            return find(self.keystone_projects(), id=project_id)
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

