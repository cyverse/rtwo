"""
Common functions used by all Openstack managers.
"""
import copy
import sys

import glanceclient
from keystoneclient.exceptions import AuthorizationFailure
from keystoneclient import exceptions
from swiftclient import client as swift_client
from novaclient import client as nova_client
from novaclient import api_versions
from neutronclient.v2_0 import client as neutron_client
from openstack import connection as openstack_sdk
from keystoneauth1.identity import v3
from keystoneauth1.session import Session
from libcloud.compute.deployment import ScriptDeployment

from threepio import logger

from rtwo.version import version_str as rtwo_version


class LoggedScriptDeployment(ScriptDeployment):

    def __init__(self, script, name=None, delete=False, logfile=None):
        """
        Use this for client-side logging
        """
        super(LoggedScriptDeployment, self).__init__(
            script, name=name, delete=delete)
        if logfile:
            self.script = self.script + " &> %s" % logfile
        #logger.info(self.script)

    def run(self, node, client):
        """
        Server-side logging
        """
        node = super(LoggedScriptDeployment, self).run(node, client)
        if self.stdout:
            logger.debug('%s (%s)STDOUT: %s' % (node.id, self.name,
                                                self.stdout))
        if self.stderr:
            logger.warn('%s (%s)STDERR: %s' % (node.id, self.name,
                                               self.stderr))
        return node


def _connect_to_swift(*args, **kwargs):
    """
    """
    if not kwargs.has_key('ex_force_auth_token'):
        swift = swift_client.Connection(*args, **kwargs)
    else:
        #RBB This is the new way to connect to swift
        #auth=v3.Token(auth_url=kwargs[u'ex_force_auth_url'],token=kwargs[u'ex_force_auth_token'])
        #sess=Session(auth=auth)
        #swift = swift_client.Connection(session=sess)
        #RBB However since an older version is being used
        swift = swift_client.Connection(preauthurl=kwargs[u'ex_force_auth_url'], preauthtoken=kwargs[u'ex_force_auth_token'])
    return swift


def _connect_to_neutron(*args, **kwargs):
    """
    """
    if not kwargs.has_key('ex_force_auth_token'):
        if 'v2.0' not in kwargs['auth_url']:
            kwargs['auth_url'] += "/v2.0"
        neutron = neutron_client.Client(*args, **kwargs)
    else:
        auth_url=kwargs[u'ex_force_auth_url']
        if auth_url.endswith('/'):
            auth_url = auth_url[:-1]
        if not 'v3' in auth_url or not 'v2' in auth_url:
            auth_url=auth_url+'/v3'
        auth=v3.Token(auth_url=auth_url,token=kwargs[u'ex_force_auth_token'],project_name=kwargs[u'ex_tenant_name'],project_domain_id='default')
        sess=Session(auth=auth)
        neutron = neutron_client.Client(session=sess)
    neutron.format = 'json'
    return neutron

def _get_os_userid_from_token(*args, **kwargs):
    if version == 'v2.0':
        from keystoneclient.v2_0 import client as ks_client
    else:
        from keystoneclient.v3 import client as ks_client
        auth_url=kwargs[u'ex_force_auth_url']
        if auth_url.endswith('/'):
            auth_url = auth_url[:-1]
        if not 'v3' in auth_url or not 'v2' in auth_url:
            auth_url=auth_url+'/v2.0'
    auth=v3.Token(auth_url=auth_url,token=kwargs[u'ex_force_auth_token'],project_name=kwargs[u'ex_tenant_name'],project_domain_id='default')
    sess=Session(auth=auth)
    logger.info(type(sess))
    return sess.get_user_id()

def _connect_to_keystone(*args, **kwargs):
    """
    """
    if not kwargs.has_key('ex_force_auth_token'):
        try:
            version = kwargs.get('version', 'v2.0')
            if version == 'v2.0':
                from keystoneclient.v2_0 import client as ks_client
            else:
                from keystoneclient.v3 import client as ks_client
            keystone = ks_client.Client(*args, **kwargs)
        except AuthorizationFailure as e:
            raise Exception("Authorization Failure: Bad keystone secrets or "
                            "firewall causing a timeout.")
    else:
      try:
        version = kwargs.get('version', 'v2.0')
        if version == 'v2.0':
            from keystoneclient.v2_0 import client as ks_client
        else:
            from keystoneclient.v3 import client as ks_client
        auth_url=kwargs[u'ex_force_auth_url']
        if auth_url.endswith('/'):
            auth_url = auth_url[:-1]
        if not 'v3' in auth_url or not 'v2' in auth_url:
            auth_url=auth_url+'/v2.0'
        auth=v3.Token(auth_url=auth_url,token=kwargs[u'ex_force_auth_token'],project_name=kwargs[u'ex_tenant_name'],project_domain_id='default')
        sess=Session(auth=auth)
        keystone = ks_client.Client(session=sess)
      except AuthorizationFailure as e:
        raise Exception("Keyston Authorization Failure")
    return keystone

def _connect_to_openstack_sdk(*args, **kwargs):
    """
    Connect to OpenStack SDK client
    """

    # Atmosphere was configured on 'v2' naming.
    # This will update the value to the current naming, 'project_name'
    from openstack import profile
    from openstack import utils
    identity_version = kwargs.get('identity_api_version', 2)
    if identity_version == 2:
        return None
    utils.enable_logging(True, stream=sys.stdout) # TODO: stream this to _not_ stdout
    user_profile = profile.Profile()
    user_profile.set_region(profile.Profile.ALL, kwargs.get('region_name'))
    if 'project_name' not in kwargs and 'tenant_name' in kwargs:
        kwargs['project_name'] = kwargs.pop('tenant_name')

    user_profile.set_version('identity', 'v%s' % identity_version)
    user_profile.set_interface('identity', 'admin')
    user_agent = "rtwo/%s" % (rtwo_version(),)
    stack_sdk = openstack_sdk.Connection(
        user_agent=user_agent,
        profile=user_profile,
        **kwargs
    )
    return stack_sdk

def _connect_to_glance(keystone, version='1', *args, **kwargs):
    """
    NOTE: We use v1 because moving up to v2 results in a LOSS OF
    FUNCTIONALITY..
    """
    if not kwargs.has_key('ex_force_auth_token'):
        glance_endpoint = keystone.service_catalog.url_for(
            service_type='image',
            endpoint_type='publicURL')
        auth_token = keystone.service_catalog.get_token()
        if type(version) == str:
            if '3' in version:
                version = 2
            elif '2' in version:
                version = 2
        glance = glanceclient.Client(version,
                                     endpoint=glance_endpoint,
                                     token=auth_token['id'])
    else:
        auth_url=kwargs[u'ex_force_auth_url']
        if auth_url.endswith('/'):
            auth_url = auth_url[:-1]
        if not 'v3' in auth_url or not 'v2' in auth_url:
            auth_url=auth_url+'/v2.0'
        auth=v3.Token(auth_url=auth_url,token=kwargs[u'ex_force_auth_token'],project_name=kwargs[u'ex_tenant_name'],project_domain_id='default')
        sess=Session(auth=auth)
        if type(version) == str:
            if '3' in version:
                version = 2
            elif '2' in version:
                version = 2
        glance = glanceclient.Client(version,session=sess)
    return glance

def _connect_to_keystoneauth(
            auth_url, username, password,
            user_domain_id, project_domain_id):
    """
    Connect to keystoneauth (Password) - The v3 way
    ..Because obviously.. So simple.
    """
    keystone_auth = v3.Password(
        auth_url, username=username,
        password=password, user_domain_id=user_domain_id,
        project_domain_id=project_domain_id)
    return keystone_auth

def _connect_to_nova(*args, **kwargs):
    if not kwargs.has_key('ex_force_auth_token'):
        kwargs = copy.deepcopy(kwargs)
        version = kwargs.pop('version', '2')
        auth_url = kwargs.pop('auth_url')
        if auth_url.endswith('/'):
            auth_url = auth_url[:-1]
        
        username = kwargs.pop('username')
        password = kwargs.pop('password')
        tenant_name = kwargs.pop('tenant_name')
        region_name = kwargs.pop('region_name')
        project_domain_id = kwargs.pop('project_domain_id','default')
        user_domain_id = kwargs.pop('user_domain_id','default')
        endpoint_type = kwargs.pop('endpoint_type','publicURL')
        service_type = kwargs.pop('service_type','compute')
        version = api_versions.APIVersion("2.0")
        password_auth = _connect_to_keystoneauth(
            auth_url, username, password,
            user_domain_id, project_domain_id)
        #kwargs['auth'] = password_auth
        kwargs['http_log_debug'] = True
        logger.info("nova password login: %s" % username)
        nova = nova_client.Client(version,
                                  username,
                                  password,
                                  tenant_name,
                                  auth_url=auth_url,
                                  region_name=region_name,
                                  #extensions = self.extensions,
                                  *args, no_cache=True, **kwargs)
    else:
        #note: this is different than the requirments for libcloud
        #      the auth_url must have the v2.0 or v3 at the end of it here
        #      but not for libcloud  auth_url+ /v2.0 or /v3
        auth_url=kwargs[u'ex_force_auth_url']
        if auth_url.endswith('/'):
            auth_url = auth_url[:-1]
        if not 'v3' in auth_url or not 'v2' in auth_url:
            auth_url=auth_url+'/v3'
        logger.info("ex_force_auth_url: %s" % kwargs[u'ex_force_auth_url'])
        logger.info("nova token login: %s --  %s, %s, %s " % (auth_url,kwargs[u'ex_force_auth_token'], kwargs[u'ex_tenant_name'], 'default'))
        auth=v3.Token(auth_url=auth_url,token=kwargs[u'ex_force_auth_token'],project_name=kwargs[u'ex_tenant_name'],project_domain_id='default')
        sess=Session(auth=auth)
        nova = nova_client.Client("2.1",session=sess)
        sec_groups = nova.servers.list()
        logger.info("sec_groups")
        logger.info(repr(sec_groups))
    return nova


def findall(manager, *args, **kwargs):
    """
        Find all items with attributes matching ``**kwargs``.

        This isn't very efficient: it loads the entire list then filters on
        the Python side.
    """
    found = []
    searches = kwargs.items()

    for obj in manager.list():
        try:
            if all(getattr(obj, attr) == value
                   for (attr, value) in searches):
                found.append(obj)
        except AttributeError:
            continue
    return found


def find(manager, **kwargs):
        """
        Find a single item with attributes matching ``**kwargs``.

        This isn't very efficient: it loads the entire list then filters on
        the Python side.
        """
        rl = findall(manager, **kwargs)
        num = len(rl)

        if num == 0:
            msg = "No %s matching %s." % (manager.resource_class.__name__,
                                          kwargs)
            raise exceptions.NotFound(404, msg)
        elif num > 1:
            raise exceptions.NoUniqueMatch
        else:
            return rl[0]
