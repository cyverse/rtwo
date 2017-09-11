"""
Common functions used by all Openstack managers.
"""
import copy
import sys

import glanceclient
import keystoneclient
from keystoneclient.exceptions import AuthorizationFailure
from keystoneclient import exceptions
from heatclient import client as heat_client
from saharaclient import client as sahara_client
from swiftclient import client as swift_client
from novaclient import client as nova_client
from novaclient import api_versions
from neutronclient.v2_0 import client as neutron_client
from openstack import connection as openstack_sdk
from keystoneauth1 import loading
from keystoneauth1 import session
from novaclient import client
from keystoneauth1 import identity
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
    if "session" in kwargs:
        session = kwargs.get("session")
        swift = swift_client.Connection(session=session)
    else:
        swift = swift_client.Connection(*args, **kwargs)
    return swift

def _connect_to_sahara(*args, **kwargs):
    """
    Recommend authenticating sahara with session auth
    """
    try:
        if "session" in kwargs:
            session = kwargs.get("session")
            sahara = sahara_client.Client("1.1", session=session, endpoint_type="internalURL")
        else:
            sahara = sahara_client.Client(*args, **kwargs)
    except RuntimeError as client_failure:
        if "Could not find Sahara endpoint" in client_failure.message:
            return None
        raise
    return sahara

def _connect_to_heat(*args, **kwargs):
    """
    Recommend authenticating heat with session auth
    """
    try:
        if "session" in kwargs:
            session = kwargs.get("session")
            heat = heat_client.Client("1", session=session)
        else:
            heat = heat_client.Client(*args, **kwargs)
    except RuntimeError as client_failure:
        if "Could not find Heat endpoint" in client_failure.message:
            return None
        raise
    return heat

def _connect_to_neutron(*args, **kwargs):
    """
    """
    neutron = neutron_client.Client(*args, **kwargs)
    neutron.format = 'json'
    return neutron

def _connect_to_keystone_password(
        auth_url, username, password,
        project_name, user_domain_name=None, project_domain_name=None, **kwargs):
    """
    Given a username and password,
    authenticate with keystone to get an unscoped token
    Exchange token to receive an auth,session,token scoped to a specific project_name and domain_name.
    """
    password_auth = identity.Password(
        auth_url=auth_url,
        username=username, password=password, project_name=project_name,
        user_domain_name=user_domain_name, project_domain_name=project_domain_name)
    password_sess = Session(auth=password_auth)
    password_token = password_sess.get_token()
    return (password_auth, password_sess, password_token)

def _connect_to_keystone_auth_v3(
        auth_url, auth_token, project_name, domain_name, **kwargs):
    """
    Give a auth_url and auth_token,
    authenticate with keystone version 3 to get a scoped_token,
    Exchange token to receive an auth, session, token scoped to a sepcific project_name and domain_name.
    """
    token_auth = identity.Token(
        auth_url=auth_url,
        token=auth_token,
        project_domain_id=domain_name,
        project_name=project_name)
    token_sess = Session(auth=token_auth)
    token_token = token_sess.get_token()
    return (token_auth, token_sess, token_token)

def _connect_to_keystone_v2(**kwargs):
    """
    DEPRECATION WARNING: Should only be used by legacy clouds
    Given a username and password,
    authenticate with keystone to get an unscoped token
    Exchange token to receive an auth,session,token scoped to a specific project_name and domain_name.
    """
    # return _connect_to_keystone_password(auth_url, username, password, project_name, **kwargs)
    from keystoneclient.v2_0 import client as ks_client
    keystone = ks_client.Client(**kwargs)
    return keystone

def _connect_to_keystone_v3(
        auth_url, username, password,
        project_name, **kwargs):
    """
    Given a username and password,
    authenticate with keystone to get an unscoped token
    Exchange token to receive an auth,session,token scoped to a specific project_name and domain_name.
    """
    domain_name = kwargs.pop('domain_name', 'default')
    project_domain_name = kwargs.pop('project_domain_name',
                            kwargs.pop('project_domain_id', domain_name))
    user_domain_name = kwargs.pop('user_domain_name',
                            kwargs.pop('user_domain_id', domain_name))
    return _connect_to_keystone_password(auth_url, username, password, project_name, user_domain_name, project_domain_name, **kwargs)

def _token_to_keystone_scoped_project(
        auth_url, token,
        project_name, domain_name="default"):
    """
    Given an auth_url and scoped/unscoped token:
    Create an auth,session and token for a specific project_name and domain_name (Required to access a serviceCatalog for neutron/nova/etc!)
    """
    auth = v3.Token(auth_url=auth_url, token=token, project_name=project_name, project_domain_id=domain_name)
    sess = Session(auth=auth)
    token = sess.get_token()
    return (auth, sess, token)



def _connect_to_keystone(*args, **kwargs):
    """
    Deprecated: keystoneclient is going away after legacy clouds have been upgraded.
    Use openstackclient instead.
    """

    try:
        raise Exception()
    except:
        logger.exception("Deprecated: keystoneclient is going away after legacy clouds have been upgraded -- convert to openstack-client/sdk")

    version = kwargs.get('version', 'v2.0')
    if version == 'v2.0':
        from keystoneclient.v2_0 import client as ks_client
        keystone = _connect_to_keystone_v2(**kwargs)
        return keystone
    from keystoneclient.v3 import client as ks_client
    if 'auth' in kwargs and 'session' in kwargs:
        (auth, sess) = (kwargs['auth'], kwargs['session'])
    else:
        (auth, sess, token) = _connect_to_keystone_v3(**kwargs)
    keystone = ks_client.Client(auth=auth, session=sess)
    if version == 'v2.0':
        keystone._adapter.version = None
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

def _connect_to_glance_by_auth(*args, **kwargs):
    """
    Use this for new Openstack Clouds
    """
    version = '2'
    glance = glanceclient.Client(version,
                                 **kwargs)
    return glance

def _connect_to_glance(keystone, version='2', *args, **kwargs):
    """
    NOTE: We use v1 because moving up to v2 results in a LOSS OF
    FUNCTIONALITY..
    """
    if type(keystone) == keystoneclient.v2_0.client.Client:
        glance_service = keystone.services.find(type='image')
        glance_endpoint_obj = keystone.endpoints.find(service_id=glance_service.id)
        glance_endpoint = glance_endpoint_obj.publicurl
    else:
        glance_endpoint = keystone.session.get_endpoint(
            service_type='image',
            endpoint_type='publicURL')
    auth_token = keystone.session.get_token()
    if type(version) == str:
        if '3' in version:
            version = 2
        elif '2' in version:
            version = 2
    glance = glanceclient.Client(version,
                                 endpoint=glance_endpoint,
                                 token=auth_token)
    return glance

def _connect_to_nova(*args, **kwargs):
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
    if version == 3:
        (password_auth, sess, token) = _connect_to_keystone_password(
            auth_url, username, password, tenant_name,
            user_domain_id, project_domain_id)
        return _connect_to_nova_by_auth(auth=password_auth, session=sess)
    # Legacy cloud path:
    version = api_versions.APIVersion("2.0")
    kwargs['http_log_debug'] = True
    nova = nova_client.Client(version,
                              username,
                              password,
                              tenant_name,
                              auth_url=auth_url,
                              region_name=region_name,
                              #extensions = self.extensions,
                              *args, no_cache=True, **kwargs)
    return nova


def _connect_to_nova_by_auth(*args, **kwargs):
    VERSION = kwargs.get('version', 2)
    if 'session' not in kwargs:
        (auth, sess, token) = _connect_to_keystone_v3(
            *args, **kwargs)
    else:
        sess = kwargs['session']
    nova = client.Client(VERSION, session=sess)
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
