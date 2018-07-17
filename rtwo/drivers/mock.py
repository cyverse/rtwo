import uuid
from libcloud.common.base import ConnectionKey
from libcloud.compute.base import Node
from libcloud.compute.base import NodeDriver
from libcloud.compute.base import KeyPair
from libcloud.compute.types import Provider, NodeState


class MockConnection(ConnectionKey):
    def connect(self, host=None, port=None):
        pass


class MockNodeDriver(NodeDriver):

    name = "Mock Node Provider"
    website = 'http://example.com'
    type = Provider.DUMMY
    all_nodes = []
    all_volumes = []
    all_instances = []
    all_images = []
    all_sizes = []

    def __init__(self, creds):
        self.creds = creds
        self.connection = MockConnection(self.creds)

    def get_uuid(self, unique_field=None):
        return str(uuid.uuid4())

    def list_nodes(self):
        return self.all_nodes

    def start_node(self, node):
        node.state = NodeState.RUNNING

    def stop_node(self, node):
        node.state = NodeState.STOPPED

    def reboot_node(self, node, reboot_type='SOFT'):
        node.state = NodeState.REBOOTING

    def resume_node(self, node):
        node.state = NodeState.RUNNING

    def suspend_node(self, node):
        node.state = NodeState.SUSPENDED

    def destroy_node(self, node, *args, **kwargs):
        node.state = NodeState.TERMINATED
        index = self.all_nodes.index(node)
        return self.all_nodes.pop(index)

    def import_key_pair_from_string(self, name, key_material):
        key_pair = KeyPair(
            name=name,
            public_key=key_material,
            fingerprint='fingerprint',
            private_key='private_key',
            driver=self)
        return key_pair

    def is_valid(self):
        return True

    def _get_size(self, alias):
        size = MockSize("Unknown", self.providerCls())
        return size

    def list_all_volumes(self, *args, **kwargs):
        """
        Return the InstanceClass representation of a libcloud node
        """
        return self.all_volumes

    def get_instance(self, instance_id, *args, **kwargs):
        """
        Return the InstanceClass representation of a libcloud node
        """
        instances = self.list_all_instances()
        instance = [inst for inst in instances if inst.id == instance_id]
        if not instance:
            return None
        return instance[0]

    def list_images(self, *args, **kwargs):
        """
        Return the MachineClass representation of a libcloud NodeImage
        """
        return self.all_images

    def list_sizes(self, *args, **kwargs):
        """
        Return the SizeClass representation of a libcloud NodeSize
        """
        return self.all_sizes

    def create_node(self,
                    id=None,
                    name=None,
                    source=None,
                    ip=None,
                    size=None,
                    extra={},
                    *args,
                    **kwargs):
        id = id or uuid.uuid4()
        name = name or 'dummy-{}'.format(id),
        node = Node(
            id=id,
            name=name,
            state=NodeState.RUNNING,
            public_ips=[ip],
            private_ips=[],
            driver=self,
            size=size,
            extra=extra,
            *args,
            **kwargs)
        self.all_nodes.append(node)
        return node

    def ex_list_all_instances(self):
        return self.all_nodes

    def ex_add_fixed_ip(self, instance, network_id):
        pass

    def ex_clean_floating_ip(*args, **kwargs):
        pass
