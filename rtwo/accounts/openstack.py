"""
UserManager:
  Remote Openstack  Admin controls..


DEPRECATION NOTE: THIS IS NOT THE ACCOUNTS/OPENSTACK.PY THAT YOU ARE LOOKING FOR!
YOU WANT THE `accounts/openstack.py` in ATMOSPHERE!

THIS FILE WILL GO AWAY VERY SOON!
"""
from hashlib import sha1
from urlparse import urlparse

from novaclient.v2 import client as nova_client
from novaclient.exceptions import OverLimit

from threepio import logger

from rtwo import settings

from rtwo.drivers.openstack_user import UserManager
from rtwo.drivers.openstack_network import NetworkManager
from rtwo.drivers.common import _connect_to_glance, _connect_to_nova,\
    _connect_to_keystone


class AccountDriver():
    user_manager = None
    network_manager = None

    def __init__(self, *args, **kwargs):
        network_args = {}


    def get_openstack_clients(self, username, password=None, tenant_name=None):

        user_creds = self._get_openstack_credentials(username,
                                                     password,
                                                     tenant_name)
        neutron = self.network_manager.new_connection(**user_creds)
        args = ()
        kwargs = user_creds
        keystone = _connect_to_keystone(*args, **kwargs)
        nova = _connect_to_nova(*args, **kwargs)
        glance = _connect_to_glance(keystone, *args, **kwargs)
        return {
            'glance': glance,
            'keystone': keystone,
            'nova': nova,
            'neutron': neutron,
            'horizon': self._get_horizon_url(keystone.tenant_id)
        }

    def _get_horizon_url(self, tenant_id):
        parsed_url = urlparse("")
        return 'https://%s/horizon/auth/switch/%s/?next=/horizon/project/' %\
            (parsed_url.hostname, tenant_id)

    def create_account(self, username, admin_role=False, max_quota=False):
        """
        Create (And Update 'latest changes') to an account

        """
        finished = False
        # Special case for admin.. Use the Openstack admin identity..
        if username == 'admin':
            ident = self.create_openstack_identity('','','')
            return ident
        #Attempt account creation
        while not finished:
            try:
                password = self.hashpass(username)
                # Retrieve user, or create user & project
                user = self.get_or_create_user(username, password,
                                               True, admin_role)
                logger.debug(user)
                project = self.get_project(username)
                logger.debug(project)
                roles = user.list_roles(project)
                logger.debug(roles)
                if not roles:
                    self.user_manager.add_project_member(username,
                                                         username,
                                                         admin_role)
                self.user_manager.build_security_group(
                    user.name,
                    self.hashpass(user.name),
                    project.name)

                finished = True

            except OverLimit:
                print 'Requests are rate limited. Pausing for one minute.'
                time.sleep(60)  # Wait one minute
        #(user, group) = self.create_usergroup(username)
        return (user, password, project) # was user

    # Useful methods called from above..
    def get_or_create_user(self, username, password=None,
                           usergroup=True, admin=False):
        user = self.get_user(username)
        if user:
            return user
        user = self.create_user(username, password, usergroup, admin)
        return user

    def create_user(self, username, password=None,
                    usergroup=True, admin=False):
        if not password:
            password = self.hashpass(username)
        if usergroup:
            (project, user, role) = self.user_manager.add_usergroup(username,
                                                                    password,
                                                                    True,
                                                                    admin)
        else:
            user = self.user_manager.add_user(username, password)
            project = self.user_manager.get_project(username)
        #TODO: Instead, return user.get_user match, or call it if you have to..
        return user

    def delete_user(self, username, usergroup=True, admin=False):
        project = self.user_manager.get_project(username)
        if project:
            self.network_manager.delete_project_network(username, project.name)
        if usergroup:
            deleted = self.user_manager.delete_usergroup(username)
        else:
            deleted = self.user_manager.delete_user(username)
        return deleted

    def hashpass(self, username):
        return sha1(username).hexdigest()

    def get_project_name_for(self, username):
        """
        This should always map project to user
        For now, they are identical..
        """
        return username

    def get_project(self, project):
        return self.user_manager.get_project(project)

    def list_projects(self):
        return self.user_manager.list_projects()

    def get_user(self, user):
        return self.user_manager.get_user(user)

    def list_users(self):
        return self.user_manager.list_users()

    def list_usergroup_names(self):
        return [user.name for (user, project) in self.list_usergroups()]

    def list_usergroups(self):
        users = self.list_users()
        groups = self.list_projects()
        usergroups = []
        for group in groups:
            for user in users:
                if user.name in group.name:
                    usergroups.append((user, group))
                    break
        return usergroups

    def _get_openstack_credentials(self, username, password=None,
                                   tenant_name=None):
        if not tenant_name:
            tenant_name = self.get_project_name_for(username)
        if not password:
            password = self.hashpass(tenant_name)
        user_creds = {'auth_url': self.user_manager.nova.client.auth_url,
                      'region_name': self.user_manager.nova.client.region_name,
                      'username': username,
                      'password': password,
                      'tenant_name': tenant_name}
        return user_creds
