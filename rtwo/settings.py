""" rtwo.settings

    Try to find usable settings. First try to use django's settings,
    if installed. Otherwise try to use test_settings.
"""
import threepio

import rtwo

try:
    from django.conf import settings
except:
    try:
        from rtwo import test_settings as settings
    except:
        pass

def set_settings(settings):
    OPENSTACK_ADMIN_KEY = settings.OPENSTACK_ADMIN_KEY
    OPENSTACK_ADMIN_SECRET = settings.OPENSTACK_ADMIN_SECRET
    OPENSTACK_AUTH_URL = settings.OPENSTACK_AUTH_URL
    OPENSTACK_ADMIN_URL = settings.OPENSTACK_ADMIN_URL
    OPENSTACK_ADMIN_TENANT = settings.OPENSTACK_ADMIN_TENANT
    OPENSTACK_DEFAULT_REGION = settings.OPENSTACK_DEFAULT_REGION
    OPENSTACK_DEFAULT_ROUTER = settings.OPENSTACK_DEFAULT_ROUTER

if settings:
    set_settings(settings)
else:
    OPENSTACK_ADMIN_KEY=""
    OPENSTACK_ADMIN_SECRET=""
    OPENSTACK_AUTH_URL=""
    OPENSTACK_ADMIN_URL=""
    OPENSTACK_ADMIN_TENANT=""
    OPENSTACK_DEFAULT_REGION="ValhallaRegion"
    OPENSTACK_DEFAULT_ROUTER="public_router"

OPENSTACK_ARGS = {
    'username': OPENSTACK_ADMIN_KEY,
    'password': OPENSTACK_ADMIN_SECRET,
    'tenant_name': OPENSTACK_ADMIN_TENANT,
    'auth_url': OPENSTACK_ADMIN_URL,
    'region_name': OPENSTACK_DEFAULT_REGION
}
OPENSTACK_NETWORK_ARGS = {
    'auth_url': OPENSTACK_ADMIN_URL,
    'region_name': OPENSTACK_DEFAULT_REGION,
    'router_name': OPENSTACK_DEFAULT_ROUTER
}

if not threepio.logger:
    threepio.initialize("rtwo")
