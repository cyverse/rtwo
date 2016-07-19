""" rtwo.settings

    Try to find usable settings. First try to use atmosphere's secrets,
    if installed. Otherwise try to use test_settings.
"""
import threepio
if not threepio.logger:
    threepio.initialize("rtwo")
from threepio import logger

try:
    # Attempt initialization from atmosphere (Using secrets)
    from atmosphere.settings import secrets as settings
    dir(settings)  # Force it to fail.
except:
    settings = None
    try:
        from rtwo import local_settings as settings
        dir(settings)  # Force it to fail.
    except:
        try:
            from rtwo import test_settings as settings
            dir(settings)  # Force it to fail.
        except:
            settings = None


if not settings:
    class Settings(object):
        pass
    settings = Settings()
    settings.EUCA_ADMIN_KEY = ""
    settings.EUCA_ADMIN_SECRET = ""
    settings.SERVER_URL = ""
    settings.INSTANCE_SERVICE_URL = ""
    settings.ATMOSPHERE_VNC_LICENSE = ""


def set_settings(settings):
    global EUCA_ADMIN_KEY, EUCA_ADMIN_SECRET, SERVER_URL,\
        INSTANCE_SERVICE_URL, ATMOSPHERE_VNC_LICENSE
    EUCA_ADMIN_KEY = settings.EUCA_ADMIN_KEY
    EUCA_ADMIN_SECRET = settings.EUCA_ADMIN_SECRET
    SERVER_URL = settings.SERVER_URL
    INSTANCE_SERVICE_URL = settings.INSTANCE_SERVICE_URL
    ATMOSPHERE_VNC_LICENSE = settings.ATMOSPHERE_VNC_LICENSE

set_settings(settings)
