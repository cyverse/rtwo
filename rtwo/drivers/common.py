"""
Common functions used by all Openstack managers.
"""
import copy

import glanceclient
from keystoneclient.exceptions import AuthorizationFailure
from keystoneclient import exceptions
from swiftclient import client as swift_client
from novaclient import client as nova_client
from neutronclient.v2_0 import client as neutron_client

from libcloud.compute.deployment import ScriptDeployment

from threepio import logger

from rtwo import settings


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
    swift = swift_client.Connection(*args, **kwargs)
    return swift


def _connect_to_neutron(*args, **kwargs):
    """
    """
    neutron = neutron_client.Client(*args, **kwargs)
    neutron.format = 'json'
    return neutron


def _connect_to_keystone(*args, **kwargs):
    """
    """
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
    if version != 'v2.0':
        keystone.management_url = keystone.management_url.replace('v2.0', 'v3')
        keystone.version = 'v3'
    return keystone


def _connect_to_glance(keystone, version='1', *args, **kwargs):
    """
    NOTE: We use v1 because moving up to v2 results in a LOSS OF
    FUNCTIONALITY..
    """
    glance_endpoint = keystone.service_catalog.url_for(
        service_type='image',
        endpoint_type='publicURL')
    auth_token = keystone.service_catalog.get_token()
    glance = glanceclient.Client(version,
                                 endpoint=glance_endpoint,
                                 token=auth_token['id'])
    return glance


def _connect_to_nova(*args, **kwargs):
    kwargs = copy.deepcopy(kwargs)
    version = kwargs.get('version', '1.1')
    region_name = kwargs.get('region_name')
    nova = nova_client.Client(version,
                              kwargs.pop('username'),
                              kwargs.pop('password'),
                              kwargs.pop('tenant_name'),
                              kwargs.pop('auth_url'),
                              kwargs.pop('region_name'),
                              *args, no_cache=True, **kwargs)
    nova.client.region_name = region_name
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


def get_ranges(uid_number, inc=0):
    """
    Return two block ranges to be used to create subnets for
    Atmosphere users.

    NOTE: If you change MAX_SUBNET then you should likely change
    the related math.
    """
    MAX_SUBNET = 4064  # Note 16 * 256
    n = uid_number % MAX_SUBNET

    #16-31
    block1 = (n + inc) % 16 + 16

    #1-254
    block2 = ((n + inc) / 16) % 254 + 1

    return (block1, block2)



def get_default_subnet(username, inc=0, get_uid_number=None):
    """
    Return the default subnet for the username and provider.

    Add and mod by inc to allow for collitions.
    """
    if get_uid_number:
        uid_number = get_uid_number(username)
    else:
        uid_number = 0

    if uid_number:
        (block1, block2) = get_ranges(uid_number, inc)
    else:
        (block1, block2) = get_ranges(0, inc)

    if username == "jmatt":
        return "172.16.42.0/24"  # /flex
    else:
        return "172.%s.%s.0/24" % (block1, block2)
