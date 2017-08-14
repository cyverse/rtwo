"""
Atmosphere service instance.

"""
from threepio import logger

from rtwo.models.provider import AWSProvider, EucaProvider, OSProvider
from rtwo.models.volume import OSVolume, Volume, MockVolume
from rtwo.models.machine import OSMachine, Machine, MockMachine
from rtwo.models.size import Size, MockSize


class Instance(object):

    owner = None
    provider = None
    source = None
    machine = NotImplementedError(
            "This field is deprecated. Use 'source' instead")
    size = None

    def _get_source_for_instance(self, node, driver):
        """
        Retrieve correct source based on instance details
        NOTE: Occasionally more data may be required/things may slow down here.
        """
        source = self._get_source_volume(node, driver)
        if source:
            return source
        source = self._get_source_snapshot(node)
        if source:
            return source
        source = self._get_source_image(node)
        return source

    def _get_source_snapshot(self, node):
        return None
    def _get_source_image(self, node):
        return None
    def _get_source_volume(self, node):
        return None


    def __init__(self, node, driver):
        self.owner = None # Should be defined per-provider
        self._node = node
        self.id = node.id
        self.alias = node.id
        self.name = node.name
        self.extra = node.extra
        self.provider = driver.provider
        self.ip = self.get_public_ip()
        self.source = self._get_source_for_instance(node, driver)

    @classmethod
    def get_instances(cls, nodes, driver):
        return [cls.provider.instanceCls(node, driver) for node in nodes]

    def get_public_ip(self):
        raise NotImplementedError()

    def get_status(self):
        raise NotImplementedError()

    def load(self):
        raise NotImplementedError()

    def save(self):
        raise NotImplementedError()

    def delete(self):
        raise NotImplementedError()

    def reset(self):
        self._node = None

    def __unicode__(self):
        return str(self)

    def __str__(self):
        return reduce(
            lambda x, y: x+y,
            map(unicode, [self.__class__, " ", self.json()]))

    def __repr__(self):
        return str(self)

    #Marked for deletion - SG
    def json(self):
        size_str = None
        source_str = None
        if not self.size:
            size_str = "None"
        elif type(self.size) == str:
            size_str = self.size
        else:
            size_str = self.size.json()
        if not self.source:
            source_str = "None"
        else:
            source_str = self.source.json()

        return {'id': self.id,
                'alias': self.alias,
                'name': self.name,
                'ip': self.ip,
                'provider': self.provider.name,
                'size': size_str,
                'source': source_str
            }


class AWSInstance(Instance):

    provider = AWSProvider

    def __init__(self, node, provider):
        Instance.__init__(self, node, provider)
        self.owner = node.extra.get('ownerId')
        self.size = node.extra.get('instance_type')
        if not self.size:
            self.size = node.extra['instancetype']
        if Size.sizes.get((provider.identifier, self.size)):
            self.size = Size.sizes[(provider.identifier, self.size)]

    def get_public_ip(self):
        if self.extra \
           and self.extra.get('dns_name'):
            return self.extra['dns_name']


class EucaInstance(AWSInstance):

    provider = EucaProvider

    def get_public_ip(self):
        if self.extra:
            return self.extra.get('dns_name')

    def get_status(self):
        """
        """
        status = "Unknown"
        if self.extra \
           and self.extra.get('status'):
            status = self.extra['status']
        return status


class OSInstance(Instance):

    provider = OSProvider

    def __init__(self, node, driver):
        Instance.__init__(self, node, driver)

        provider = driver.provider
        #Unfortunately we can't get the tenant_name..
        self.owner = node.extra.get('tenantId')
        #New in 0.2.11 - use MockSize and expect user to lookup size.id if they want more than a MockSize!
        if not self.size:
            self.size = self._get_flavor_for_instance(node)


    def _get_source_volume(self, node, driver):
        """
        Returns None or OSVolume
        """
        # Do not check for volume-as-source if no volume is attached.
        attachments = node.extra.get('attachments',{})
        if not attachments:
            attachments = node.extra.get('os-extended-volumes:volumes_attached', {})
        if not attachments:
            attachments = node.extra.get('volumes_attached')
        if not attachments:
            return None
        volume = self._test_node_is_booted_volume(driver, node, attachments)
        if not volume:
            return None
        source = OSVolume(volume)
        source._volume = None  # FIXME: This is done to avoid un-pickleable errors. A refactor of rtwo should _REMOVE_ the idea of '.source' and these complex/compound objects.
        return source

    def _test_node_is_booted_volume(self, driver, node, attachments=[]):
        """
        Given a node and a volume_id, return 'volume' if the node
        is 'running' the volume, otherwise return None 
        """
        instance_id = node.id
        if not attachments:
            attachments = node.extra['object'].get('os-extended-volumes:volumes_attached')
        for volume in attachments:
            volume_id = volume.get('id')
            volume = driver._connection.ex_get_volume(volume_id)
            if not volume:
                logger.info("[BADDATA] Volume %s listed in 'attached_volumes' but did not"
                            " return a volume" % volume_id)
                continue
            volume_attachment_data = volume.extra['attachments']
            if not volume_attachment_data:
                logger.info("[BADDATA] Volume %s listed in 'attached_volumes' but did not"
                            " return attachment data." % volume_id)
                continue
            for attach_data in volume_attachment_data:
                if attach_data['serverId'] == instance_id:
                    device = attach_data.get("device")
                    if device and 'vda' in device:
                        return volume
        #Normal behavior, this is NOT a booted volume.
        # logger.debug("Volume %s listed in 'attached_volumes' but is NOT "
        #              "currently running as an instance." % volume_id)
        return None

    def _get_source_image(self, node):
        """
        NOTE: Always returns a correct source
        That source may be a 'MockMachine' or an 'OSMachine'
        """
        image_id = node.extra.get('imageId')
        if not image_id:
            image_id = node.extra.get('image_id')
        if not image_id:
            return None
        machine = self.provider.machineCls.lookup_cached_machine(image_id,
                self.provider.identifier)
        if not machine:
            machine = MockMachine(node.extra['imageId'], self.provider)
        return machine

    def _get_flavor_for_instance(self, node):
        #Step 1, pure-cache lookup
        size = self.provider.sizeCls.lookup_size(node.extra['flavorId'],
                self.provider)
        if not size:
            size = MockSize(node.extra['flavorId'], self.provider)
        return size

    def get_status(self):
        """
        TODO: If openstack: Use extra['task'] and extra['power']
        to determine the appropriate status.
        """
        status = "Unknown"
        if self.extra \
           and self.extra.get('status'):
            status = self.extra['status']
            task = self.extra.get('task')
            if task:
                status += ' - %s' % self.extra['task']
            extra_status = self.extra.get('metadata', {}).get('tmp_status')
            if extra_status and not task and status == 'active':
                status += ' - %s' % extra_status

        return status

    def get_public_ip(self):
        if hasattr(self, "ip"):
            return self.ip
        if self._node and self._node.public_ips:
            return self._node.public_ips[0]
