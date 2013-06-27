""" rtwo.settings

    Try to find usable settings. First try to use django's settings,
    if installed. Otherwise try to use test_settings.
"""

try:
    from django.conf.settings import *
except:
    try:
        from rtwo.test_settings import *
    except:
        pass
