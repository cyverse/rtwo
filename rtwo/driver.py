"""
Atmosphere service driver.

Driver classes define interfaces and implement functionality using providers.
"""
from abc import ABCMeta, abstractmethod
import copy
from datetime import datetime
import sys
import time

from libcloud.compute.deployment import ScriptDeployment
from libcloud.compute.deployment import MultiStepDeployment
from libcloud.compute.types import DeploymentError

from threepio import logger

from rtwo import settings
from rtwo.drivers.common import LoggedScriptDeployment

from rtwo.exceptions import MissingArgsException, ServiceException

from rtwo.models.provider import AWSProvider
from rtwo.models.provider import EucaProvider
from rtwo.models.provider import OSProvider

from rtwo.models.identity import AWSIdentity
from rtwo.models.identity import EucaIdentity
from rtwo.models.identity import OSIdentity

from rtwo.mixins.driver import APIFilterMixin, MetaMixin,\
    InstanceActionMixin


class BaseDriver():
    """
    BaseDriver lists a basic set of expected functionality for an esh-driver.
    Abstract class - Should not be instantiated!!
    """

    __metaclass__ = ABCMeta

    _connection = None

    identity = None

    provider = None

    identityCls = None

    providerCls = None

    @abstractmethod
    def __init__(self, identity, provider):
        raise NotImplementedError

    @abstractmethod
    def list_instances(self, *args, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def list_machines(self, *args, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def list_sizes(self, *args, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def list_locations(self, *args, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def create_instance(self, *args, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def deploy_instance(self, *args, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def reset_network(self, *args, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def reboot_instance(self, *args, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def destroy_instance(self, *args, **kwargs):
        raise NotImplementedError

    def start_instance(self, *args, **kwargs):
        raise NotImplementedError

    def stop_instance(self, *args, **kwargs):
        raise NotImplementedError

    def resume_instance(self, *args, **kwargs):
        raise NotImplementedError

    def suspend_instance(self, *args, **kwargs):
        raise NotImplementedError

    def resize_instance(self, *args, **kwargs):
        raise NotImplementedError


class VolumeDriver():
    """
    VolumeDriver provides basic storage volume functionality for libcloud
    or esh-drivers.
    Abstract class - Should not be instantiated!!
    """
    __metaclass__ = ABCMeta

    @abstractmethod
    def list_volumes(self, *args, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def create_volume(self, *args, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def destroy_volume(self, *args, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def boot_volume(self, *args, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def attach_volume(self, *args, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def detach_volume(self, *args, **kwargs):
        raise NotImplementedError


class LibcloudDriver(BaseDriver, VolumeDriver, APIFilterMixin):
    """
    Provides direct access to the libcloud methods and data.
    """

    def __init__(self, provider, identity, **provider_credentials):
        if provider is None or identity is None:
            raise MissingArgsException(
                'LibcloudDriver is Missing Required Identity and/or Provider.')
        self.identity = identity
        self.provider = provider
        self._connection = self.provider.get_driver(
                                            self.identity,
                                            **provider_credentials)

    def list_instances(self, *args, **kwargs):
        return self._connection.list_nodes()

    def list_machines(self, *args, **kwargs):
        logger.debug("Call made to list_machines: %s - %s"
                     % (self.provider.identifier,
                     self.identity.credentials['key']))
        return self._connection.list_images()

    def list_sizes(self, *args, **kwargs):
        logger.debug("Call made to list_sizes: %s - %s"
                     % (self.provider.identifier,
                     self.identity.credentials['key']))
        return self._connection.list_sizes()

    def list_locations(self, *args, **kwargs):
        return self._connection.list_locations()

    def create_instance(self, *args, **kwargs):
        return self._connection.create_node(*args, **kwargs)

    def deploy_instance(self, *args, **kwargs):
        return self._connection.deploy_node(*args, **kwargs)

    def reset_network(self, *args, **kwargs):
        return self._connection.reset_network(*args, **kwargs)

    def reboot_instance(self, *args, **kwargs):
        return self._connection.reboot_node(*args, **kwargs)

    def destroy_instance(self, *args, **kwargs):
        return self._connection.destroy_node(*args, **kwargs)

    def list_volumes(self, *args, **kwargs):
        return self._connection.list_volumes(*args, **kwargs)

    def create_volume(self, *args, **kwargs):
        return self._connection.create_volume(*args, **kwargs)

    def destroy_volume(self, *args, **kwargs):
        return self._connection.destroy_volume(*args, **kwargs)

    def attach_volume(self, *args, **kwargs):
        return self._connection.attach_volume(*args, **kwargs)

    def detach_volume(self, *args, **kwargs):
        return self._connection.detach_volume(*args, **kwargs)


class EshDriver(LibcloudDriver, MetaMixin):
    """
    """

    @classmethod
    def settings_init(cls):
        raise ServiceException('Settings init not available for this class')

    def __init__(self, provider, identity, **provider_credentials):
        super(EshDriver, self).__init__(provider, identity, **provider_credentials)
        if not(isinstance(provider, self.providerCls)
           and isinstance(identity, self.identityCls)):
            raise ServiceException('Wrong Provider or Identity')

    def list_all_volumes(self, *args, **kwargs):
        """
        Return the InstanceClass representation of a libcloud node
        """
        return self.provider.volumeCls.get_volumes(
            self._connection.ex_list_all_volumes())

    def list_all_instances(self, **kwargs):
        """
        Return the InstanceClass representation of a libcloud node
        """
        return self.provider.instanceCls.get_instances(
            self._connection.ex_list_all_instances(), self.provider)

    def get_instance(self, instance_id, *args, **kwargs):
        """
        Return the InstanceClass representation of a libcloud node
        """
        instances = self.list_all_instances()
        instance = [inst for inst in instances if inst.id == instance_id]
        if not instance:
            return None
        return instance[0]

    def list_instances(self, **kwargs):
        """
        Return the InstanceClass representation of a libcloud node
        """
        return self.provider.instanceCls.get_instances(
            super(EshDriver, self).list_instances(), self.provider)

    def list_machines(self, *args, **kwargs):
        """
        Return the MachineClass representation of a libcloud NodeImage
        """
        return self.provider.machineCls.get_cached_machines(
            self.provider.identifier,
            super(EshDriver, self).list_machines, *args, **kwargs)

    def list_sizes(self, *args, **kwargs):
        """
        Return the SizeClass representation of a libcloud NodeSize
        """
        return self.provider.sizeCls.get_sizes(
            self.provider,
            super(EshDriver, self).list_sizes)

    def list_locations(self, *args, **kwargs):
        return super(EshDriver, self).list_locations()

    def create_instance(self, *args, **kwargs):
        """
        Return the InstanceClass representation of a libcloud node
        """
        logger.debug(str(args))
        logger.debug(str(kwargs))
        return self.provider.instanceCls(
            super(EshDriver, self).create_instance(*args, **kwargs),
            self.provider)

    def deploy_instance(self, *args, **kwargs):
        return self.provider.instanceCls(
            super(EshDriver, self).deploy_instance(*args, **kwargs),
            self.provider)

    def reset_network(self, *args, **kwargs):
        return super(EshDriver, self).reset_network(*args, **kwargs)

    def reboot_instance(self, *args, **kwargs):
        return super(EshDriver, self).reboot_instance(*args, **kwargs)

    def start_instance(self, *args, **kwargs):
        return super(EshDriver, self).start_instance(*args, **kwargs)

    def stop_instance(self, *args, **kwargs):
        return super(EshDriver, self).stop_instance(*args, **kwargs)

    def resume_instance(self, *args, **kwargs):
        return super(EshDriver, self).resume_instance(*args, **kwargs)

    def suspend_instance(self, *args, **kwargs):
        return super(EshDriver, self).suspend_instance(*args, **kwargs)

    def destroy_instance(self, *args, **kwargs):
        return super(EshDriver, self).destroy_instance(*args, **kwargs)

    def boot_volume(self, *args, **kwargs):
        return self.provider.instanceCls(
                super(EshDriver, self).boot_volume(*args, **kwargs),
                self.provider)

    def list_volumes(self, *args, **kwargs):
        return self.provider.volumeCls.get_volumes(
            super(EshDriver, self).list_volumes(*args, **kwargs))

    def create_volume(self, *args, **kwargs):
        return super(EshDriver, self).create_volume(*args, **kwargs)

    def destroy_volume(self, *args, **kwargs):
        return super(EshDriver, self).destroy_volume(*args, **kwargs)

    def attach_volume(self, *args, **kwargs):
        return super(EshDriver, self).attach_volume(*args, **kwargs)

    def detach_volume(self, *args, **kwargs):
        return super(EshDriver, self).detach_volume(*args, **kwargs)


class OSDriver(EshDriver, InstanceActionMixin):
    """
    """
    providerCls = OSProvider

    identityCls = OSIdentity

    @classmethod
    def admin_init(cls, id_credentials, prov_credentials):
        """
        To be used instead of settings_init, Expects the following keys for
        each credentials dict:
        id_credentials:
        * Username
        * Password
        * (Tenant/Project) Name
        Prov_credentials:
        * region_name
        * auth_url
        """
        try:
            username = id_credentials.pop('username')
            password = id_credentials.pop('password')
            tenant_name = id_credentials.pop('tenant_name')
        except:
            raise ServiceException(
                'Settings init not available for this class:'
                'Expected settings.OPENSTACK_ARGS with'
                'username/password/tenant_name fields')
        OSProvider.set_meta()
        provider = OSProvider()
        identity = OSIdentity(provider, username, password,
                              ex_tenant_name=tenant_name,
                              **prov_credentials)
        driver = cls(provider, identity)
        return driver

    @classmethod
    def settings_init(cls):
        """
        DEPRECATED:
        """
        os_args = {}
        try:
            username = os_args.pop('username')
            password = os_args.pop('password')
            tenant_name = os_args.pop('tenant_name')
        except:
            raise ServiceException(
                'Settings init not available for this class:'
                'Expected settings.OPENSTACK_ARGS with'
                'username/password/tenant_name fields')
        OSProvider.set_meta()
        provider = OSProvider()
        identity = OSIdentity(provider, username, password,
                              ex_tenant_name=tenant_name)
        driver = cls(provider, identity)
        return driver

    def __init__(self, provider, identity, **provider_credentials):
        super(OSDriver, self).__init__(provider, identity, **provider_credentials)
        #Set connection && force_service_region
        self._connection._ex_force_service_region =\
        self._connection.connection.service_region =\
            provider.options.get('region_name')

    def list_machines(self, *args, **kwargs):
        """
        This openstack specific implementation caches machine lists
        using tenant_name as the identifier

        Return the MachineClass representation of a libcloud NodeImage
        """
        #TODO: I don't like this implementation.. -Steve
        # Currently there is no 'override' if i dont want to use ex-tenant-name
        identifier = self.identity.credentials.get('ex_tenant_name')
        if not identifier:
            logger.debug("Could not find tenant_name, "
                         "falling back to provider identifier")
            identifier = self.provider.identitifier
        return self.provider.machineCls.get_cached_machines(
            identifier,
            super(EshDriver,self).list_machines, *args, **kwargs)


    def deploy_init_to(self, *args, **kwargs):
        """
        Creates a multi script deployment to prepare and call
        the latest init script
        TODO: Add versioning for 30+
        """
        if args:
            instance = args[0]
        else:
            raise MissingArgsException("Missing instance argument.")
        if isinstance(self.identity.user, basestring):
            username = self.identity.user
        else:
            # Django.contrib.auth.models.User
            username = self.identity.user.username
        atmo_init = "/usr/sbin/atmo_init_full.py"
        server_atmo_init = "/init_files/30/atmo_init_full.py"
        script_init = ScriptDeployment(
            'if [ ! -d "/var/log/atmo" ];then\n'
            'mkdir -p /var/log/atmo\n'
            'fi\n'
            'if [ ! -f "/var/log/atmo/deploy.log" ]; then\n'
            'touch /var/log/atmo/deploy.log\n'
            'fi',
            name="./deploy_init_log.sh")
        #These requirements are for Editors, Shell-in-a-box
        do_ubuntu = "apt-get update;apt-get install -y emacs vim wget "\
                    + "language-pack-en make gcc g++ gettext texinfo "\
                    + "autoconf automake"
        do_centos = "yum install -y emacs vim-enhanced wget make "\
                    + "gcc gettext texinfo autoconf automake python-simplejson"
        script_deps = LoggedScriptDeployment(
            "distro_cat=`cat /etc/*-release`\n"
            + "if [[ $distro_cat == *Ubuntu* ]]; then\n"
            + do_ubuntu
            + "\nelse if [[ $distro_cat == *CentOS* ]];then\n"
            + do_centos
            + "\nfi\nfi",
            name="./deploy_deps.sh",
            logfile="/var/log/atmo/deploy.log")
        script_wget = LoggedScriptDeployment(
            "wget -O %s %s%s" % (atmo_init, settings.SERVER_URL,
                                 server_atmo_init),
            name='./deploy_wget_atmoinit.sh',
            logfile='/var/log/atmo/deploy.log')
        script_chmod = LoggedScriptDeployment(
            "chmod a+x %s" % atmo_init,
            name='./deploy_chmod_atmoinit.sh',
            logfile='/var/log/atmo/deploy.log')
        instance_token = kwargs.get('token', '')
        if not instance_token:
            instance_token = instance.id
        awesome_atmo_call = "%s --service_type=%s --service_url=%s"
        awesome_atmo_call += " --server=%s --user_id=%s"
        awesome_atmo_call += " --token=%s --name=\"%s\""
        awesome_atmo_call += " --vnc_license=%s"
        awesome_atmo_call %= (
            atmo_init,
            "instance_service_v1",
            settings.INSTANCE_SERVICE_URL,
            settings.SERVER_URL,
            username,
            instance_token,
            instance.name,
            settings.ATMOSPHERE_VNC_LICENSE)
        #kludge: weirdness without the str cast...
        str_awesome_atmo_call = str(awesome_atmo_call)
        #logger.debug(isinstance(str_awesome_atmo_call, basestring))
        script_atmo_init = LoggedScriptDeployment(
            str_awesome_atmo_call,
            name='./deploy_call_atmoinit.sh',
            logfile='/var/log/atmo/deploy.log')
        script_rm_scripts = LoggedScriptDeployment(
            "rm -rf ~/deploy_*",
            name='./deploy_remove_scripts.sh',
            logfile='/var/log/atmo/deploy.log')
        msd = MultiStepDeployment([script_init,
                                   script_deps,
                                   script_wget,
                                   script_chmod,
                                   script_atmo_init,
                                   script_rm_scripts])
        kwargs.update({'deploy': msd})

        private_key = "/opt/dev/atmosphere/extras/ssh/id_rsa"
        kwargs.update({'ssh_key': private_key})

        kwargs.update({'timeout': 120})

        return self.deploy_to(instance, *args, **kwargs)

    def deploy_to(self, *args, **kwargs):
        """
        Deploy to an instance.
        """
        if args:
            instance = args[0]
        else:
            raise MissingArgsException("Missing instance argument.")
        if not kwargs.get('deploy'):
            raise MissingArgsException("Missing deploy argument.")
        if not kwargs.get('ssh_key'):
            private_key = "/opt/dev/atmosphere/extras/ssh/id_rsa"
            kwargs.update({'ssh_key': private_key})
        if not kwargs.get('timeout'):
            kwargs.update({'timeout': 120})

        #Scrub deploy steps if they exist.
        deploy = kwargs.get('deploy')
        if hasattr(deploy, "steps"):
            deploy.steps = [s for s in deploy.steps if s is not None]

        logger.info("Attempting deployment to node")
        node = instance
        #Get the libcloud node, not the eshInstance
        if hasattr(instance, '_node'):
            node = instance._node
        self._connection.ex_deploy_to_node(node,
                                           *args, **kwargs)
        return True

    def deploy_instance(self, *args, **kwargs):
        """
        Deploy instance.

        NOTE: This is blocking and uses the blocking create_node.
        """
        if not kwargs.get('deploy'):
            raise MissingArgsException("Missing deploy argument.")
        username = self.identity.user.username

        private_key = "/opt/dev/atmosphere/extras/ssh/id_rsa"
        kwargs.update({'ssh_key': private_key})
        kwargs.update({'timeout': 120})

        #cloudinit_script = prepare_cloudinit_script()
        #kwargs.update({'ex_userdata': cloudinit_script})
        try:
            self.deploy_node(*args, **kwargs)
        except DeploymentError as de:
            logger.error(sys.exc_info())
            logger.error(de.value)
            return False
        return True

    def destroy_instance(self, *args, **kwargs):
        return self._connection.destroy_node(*args, **kwargs)

    def start_instance(self, *args, **kwargs):
        return self._connection.ex_start_node(*args, **kwargs)

    def stop_instance(self, *args, **kwargs):
        return self._connection.ex_stop_node(*args, **kwargs)

    def suspend_instance(self, *args, **kwargs):
        return self._connection.ex_suspend_node(*args, **kwargs)

    def resume_instance(self, *args, **kwargs):
        return self._connection.ex_resume_node(*args, **kwargs)

    def resize_instance(self, *args, **kwargs):
        return self._connection.ex_resize(*args, **kwargs)

    def reset_network(self, *args, **kwargs):
        return self._connection.reset_network(*args, **kwargs)

    def reboot_instance(self, *args, **kwargs):
        return self._connection.reboot_node(*args, **kwargs)

    def boot_volume(self, *args, **kwargs):
        return self._connection.ex_boot_volume(*args, **kwargs)

    def confirm_resize_instance(self, *args, **kwargs):
        return self._connection.ex_confirm_resize(*args, **kwargs)

    def revert_resize_instance(self, *args, **kwargs):
        return self._connection.ex_revert_resize(*args, **kwargs)

    def _add_floating_ip(self, instance, *args, **kwargs):
        return self._connection.neutron_associate_ip(instance, *args, **kwargs)

    def _del_floating_ip(self, instance, *args, **kwargs):
        return self._connection.neutron_disassociate_ip(instance, *args, **kwargs)

    def _clean_floating_ip(self, *args, **kwargs):
        return self._connection.ex_clean_floating_ip(**kwargs)

    def _is_inactive_instance(self, instance):
        #Other things may need to be tested
        status = instance.extra['status']
        task = instance.extra['task']
        power = instance.extra['power']
        if status in ['paused',
                'suspended','stopped','shutoff',]:
            return True
        if task in ['suspending','shutting-off',
                    ]:
            return True
        return False

    def _is_active_instance(self, instance):
        #Other things may need to be tested
        status = instance.extra['status']
        task = instance.extra['task']
        power = instance.extra['power']
        if status in ['active','build','resize']:
            if task in ['deleting', 'suspending']:
                result=False
            result=True
        elif task in ['resuming', 'powering-on',
                    'verify-resize', 'resize_reverting', 'resize_confirming']:
            result=True
        else:
            result=False
        logger.info("Instance: %s Status: %s-%s Active:%s" % (instance.id,
            status, task, result))
        return result


class AWSDriver(EshDriver):
    """
    """
    providerCls = AWSProvider

    identityCls = AWSIdentity

    def deploy_instance(self, *args, **kwargs):
        """
        Deploy an AWS node.
        """
        username = self.identity.user.username
        atmo_init = "/usr/sbin/atmo_init_full.py"
        server_atmo_init = "/init_files/30/atmo_init_full.py"
        script_deps = ScriptDeployment(
            "sudo apt-get install -y emacs vim wget")
        script_wget = ScriptDeployment(
            "sudo wget -O %s %s%s" %
            (atmo_init, settings.SERVER_URL, server_atmo_init))
        script_chmod = ScriptDeployment("sudo chmod a+x %s" % atmo_init)
        instance_token = kwargs.get('token', '')
        awesome_atmo_call = "sudo %s --service_type=%s --service_url=%s"
        awesome_atmo_call += " --server=%s --user_id=%s --token=%s"
        awesome_atmo_call += " --name=%s &> %s"
        awesome_atmo_call %= (
            atmo_init,
            "instance_service_v1",
            settings.INSTANCE_SERVICE_URL,
            settings.SERVER_URL,
            username,
            instance_token,
            kwargs.get('name', ''),
            '/var/log/atmo_init_full.err')
        logger.debug(awesome_atmo_call)
        str_awesome_atmo_call = str(awesome_atmo_call)
        #kludge: weirdness without the str cast...
        script_atmo_init = ScriptDeployment(str_awesome_atmo_call)
        private_key = ("/opt/dev/atmosphere/extras/ssh/id_rsa")
        scripts = [script_deps,
                   script_wget,
                   script_chmod,
                   script_atmo_init]
        for s in scripts:
            logger.debug(s.name)
            s.name = s.name.replace('/root', '/home/ubuntu')
            logger.debug(s.name)
        msd = MultiStepDeployment(scripts)
        kwargs.update({'ex_keyname': 'dalloway-key'})
        kwargs.update({'ssh_username': 'ubuntu'})
        kwargs.update({'ssh_key': private_key})
        kwargs.update({'deploy': msd})
        kwargs.update({'timeout': 400})

        instance = super(AWSDriver, self).deploy_instance(*args, **kwargs)
        created = datetime.strptime(instance.extra['created'],
                                    "%Y-%m-%dT%H:%M:%SZ")
        # NOTE: Removed for rtwo port. Moved to service tasks.
        # send_instance_email(username, instance.id, instance.ip,
        # created, username)
        return instance


    def create_volume(self, *args, **kwargs):
        if 'description' in kwargs:
            kwargs.pop('description')
        return super(EshDriver, self).create_volume(*args, **kwargs)


class EucaDriver(EshDriver):
    """
    """
    providerCls = EucaProvider

    identityCls = EucaIdentity

    def deploy_instance(self, *args, **kwargs):
        raise NotImplementedError

    def resume_instance(self, *args, **kwargs):
        raise NotImplementedError

    def suspend_instance(self, *args, **kwargs):
        raise NotImplementedError

    def start_instance(self, *args, **kwargs):
        raise NotImplementedError

    def stop_instance(self, *args, **kwargs):
        raise NotImplementedError
