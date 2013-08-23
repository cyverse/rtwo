import os

from libcloud.common.base import ConnectionUserAndKey, RawResponse
from libcloud.storage.base import Object, Container, StorageDriver

from libcloud.storage.types import ContainerIsNotEmptyError
from libcloud.storage.types import InvalidContainerNameError
from libcloud.storage.types import ContainerDoesNotExistError
from libcloud.storage.types import ObjectDoesNotExistError
from libcloud.storage.types import ObjectHashMismatchError

from irods.session import iRODSSession
from irods.models import Collection, User, DataObject

#from threepio.logger import logger

"""
iRODS data store
Requires 'pycommands' in addition to libcloud
"""


class IRODSConnection(ConnectionUserAndKey):
    """
    iRODS connection that accepts user_id and key
    """

    def __init__(self, username, password, host, port, zone, **kwargs):
        print 'connection init:', username, password, host, port, zone
        self.user_id = username
        self.key = password
        self.host = host
        self.port = port
        self.zone = zone


    def connect(self, host=None, port=None, base_url=None):
        if not host:
            host = self.host
        if not port:
            port = self.port
        print 'connection connect:', self.user_id, self.key, host, port, self.zone
        session = iRODSSession(host=host, port=port,
                                  user=self.user_id, password=self.key,
                                  zone=self.zone)
        self.session = session
        return session
        
    
class IRODSDriver(StorageDriver):
    name = 'iRODS Data Store'
    website = 'http://www.irods.org/'
    hash_type = 'md5'
    connectionCls = IRODSConnection

    def __init__(self, key, secret=None, host=None, port=None, zone=None, base_dir=None, **kwargs):
        self.key = key
        self.secret = secret
        self.zone = zone

        args = [self.key]

        if self.secret is not None:
            args.append(self.secret)
        if host is not None:
            args.append(host)
        if port is not None:
            args.append(port)
        if self.zone is not None:
            args.append(self.zone)
        if not base_dir:
            base_dir = '/%s/home/%s' % (self.zone, self.key)
        self.base_dir = base_dir

        print 'driver args: %s' % args
        self.connection = self.connectionCls(*args,
            **self._ex_connection_class_kwargs())

        self.connection.driver = self
        self.connection.connect()

    def iterate_containers(self):
        """
        Return a generator of containers.

        @return: A generator of Container instances.
        @rtype: C{generator} of L{Container}
        """
        base_container = self.connection.session.collections.get(self.base_dir)
        if not base_container:
            raise LibcloudError(
                'Failed to retrieve containers from base container:%s' % self.base_dir,
                driver=self)
        #containers = self._to_containers(obj=base_container.subcollections)
        #return containers
        for collection in base_container.subcollections:
            yield self._to_container(collection)
    def list_containers(self):
        """
        Return a list of containers.

        @return: A list of Container instances.
        @rtype: C{list} of L{Container}
        """
        base_container = self.connection.session.collections.get(self.base_dir)
        if not base_container:
            raise LibcloudError(
                'Failed to retrieve containers from base container:%s' % self.base_dir,
                driver=self)
        containers = self._to_containers(obj=base_container.subcollections)
        return containers

    def list_container_objects(self, container, ex_prefix=None):
        """
        Return a list of objects for the given container.

        :param container: Container instance.
        :type container: :class:`Container`

        :param ex_prefix: Only return objects starting with ex_prefix
        :type ex_prefix: ``str``

        :return: A list of Object instances.
        :rtype: ``list`` of :class:`Object`
        """
        #TODO: Filter on ex_prefix
        return self._get_objects(container)

    def iterate_container_objects(self, container, ex_prefix=None):
        """
        Return a generator of objects for the given container.

        :param container: Container instance
        :type container: :class:`Container`

        :param ex_prefix: Only return objects starting with ex_prefix
        :type ex_prefix: ``str``

        :return: A generator of Object instances.
        :rtype: ``generator`` of :class:`Object`
        """
        #TODO: Filter on ex_prefix
        return iter(self._get_objects(container))

    def get_container(self, container_name):
        #TODO: Attach irods base_dir?
        try:
            collection = self.connection.session.collections.get(container_name)
        except: #CollectionDoesNotExist
            raise ContainerDoesNotExistError(value=None,
                                             driver=self,
                                             container_name=container.name)
        return self._to_container(collection)

    def get_object(self, container_name, object_name):
        try:
            container = self.get_container(container_name)
            obj_path = self._get_object_path(container, object_name)
            data_obj = self.connection.session.data_objects.get(obj_path)
        except: #MultipleResultsFound, DataObjectDoesNotExist
            raise ObjectDoesNotExistError(value=None, driver=self,
                                      object_name=object_name)
        return self._to_obj(data_obj, container)


    def create_container(self, container_name):
        """
        Create a new container with path 'container_name'
        """
        self._check_container_name(container_name)
        try:
            new_collection = self.connection.session.collections.create(container_name)
            return self._to_container(new_collection)
        except: #CATALOG_ALREADY_HAS_ITEM_BY_THAT_NAME
            raise InvalidContainerNameError(
                value='Container with this name already exists. The name must '
                      'be unique among all the containers in the system',
                container_name=container_name, driver=self)

    def delete_container(self, container):
        # Note: All the objects in the container must be deleted first
        
        for obj in self._get_objects(container):
            raise ContainerIsNotEmptyError(value='Container is not empty',
                                container_name=container.name, driver=self)
        
        try:
            self.connection.session.collections.delete(container.name)
            return True
        except: #CollectionDoesNotExist
            raise ContainerDoesNotExistError(value=None,
                                             driver=self,
                                             container_name=container.name)


    def download_object(self, obj, destination_path, overwrite_existing=False,
                        delete_on_failure=True):
        """
        Download an object to the specified destination path.

        @param obj: Object instance.
        @type obj: L{Object}

        @param destination_path: Full path to a file or a directory where the
                                incoming file will be saved.
        @type destination_path: C{str}

        @param overwrite_existing: True to overwrite an existing file,
            defaults to False.
        @type overwrite_existing: C{bool}

        @param delete_on_failure: True to delete a partially downloaded file if
        the download was not successful (hash mismatch / file size).
        @type delete_on_failure: C{bool}

        @return: True if an object has been successfully downloaded, False
        otherwise.
        @rtype: C{bool}
        """

        base_container = os.path.basename(destination_path)
        try:
            collection = self.connection.session.collections.get(base_continer)
        except: #CollectionDoesNotExist
            raise LibcloudError(
                value='Container %s does not exist,' % (base_container) +
                'cannot place object in %s' % (destination_path),
                driver=self)
        #Container exists, attempt to create new file
        #TODO: if overwrite=True, check for and delete/reuse object first.
        try:
            new_obj = self.connection.session.data_objects.create(destination_path)
        except: #CollectionDoesNotExist
            raise LibcloudError(
                value='Could not create new object at ' % (destination_path),
                driver=self)
        #Then write to the new file
        #TODO: What am I writing?
        return True

    def download_object_as_stream(self, obj, chunk_size=None):
        raise NotImplementedError()

    def upload_object(self, file_path, container, object_name, extra=None,
                      verify_hash=True):
        """
        Upload an object currently located on a disk.

        @param file_path: Path to the object on disk.
        @type file_path: C{str}

        @param container: Destination container.
        @type container: L{Container}

        @param object_name: Object name.
        @type object_name: C{str}

        @param verify_hash: Verify hash
        @type verify_hash: C{bool}

        @param extra: (optional) Extra attributes (driver specific).
        @type extra: C{dict}

        @rtype: C{object}
        """
        object_path = self._get_object_path(obj.container, obj.name)
        data_object = self.connection.session.data_objects.get(object_path)
        
        with data_object.open('w') as f_to_write:
            with open(file_path,'r') as f_to_read:
                for line in f_to_read:
                    f_to_write.write(line)
        return True

    def delete_object(self, obj):
        object_path = self._get_object_path(obj.container, obj.name)
        try:
            self.connection.session.data_objects.delete(object_path)
            return True
        except: #DataObjectDoesNotExist
            raise ObjectDoesNotExistError(value=None, driver=self,
                                          object_name=obj.name)


    def _get_objects(self, container):
        """
        Iterate through all data_objects on iRODS container

        TODO: See if we can implement an os.walk() in pyrods
        TODO: Recursively iterate through iRODS container and return the objects found
        """
        
        collection = self.connection.session.collections.get(container.name)
        data_files = collection.data_objects
        return [self._to_obj(datafile) for datafile in data_files]

    def _get_container_path(self, container):
        """
        Return a container path

        @param container: Container instance
        @type  container: L{Container}

        @return: A path for this container.
        @rtype: C{str}
        """
        #TODO: Maybe add base_dir to this?
        return '%s' % (container.name)

    def _get_object_path(self, container, object_name):
        """
        Return path of object on iRODS File System

        @param container: Container instance
        @type  container: L{Container}

        @param object_name: Object name
        @type  object_name: L{str}

        @return: A  path for this object.
        @rtype: C{str}
        """
        container_url = self._get_container_path(container)
        object_name_cleaned = self._clean_object_name(object_name)
        object_path = '%s/%s' % (container_url, object_name_cleaned)
        return object_path

    def _clean_object_name(self, name):
        """
        These rules define 'allowable' names.
        """
        name = name.replace('\\','').replace('/','')
        return name

    def _check_container_name(self, container_name):
        """
        Check if the container name is valid

        @param container_name: Container name
        @type container_name: C{str}
        """

        if '/' in container_name or '\\' in container_name:
            raise InvalidContainerNameError(value=None, driver=self,
                                            container_name=container_name)

    def _to_containers(self, obj):
        for subcol in obj:
            yield self._to_container(element)

    def _to_objs(self, obj, container):
        return [self._to_obj(element, container) for element in obj]

    def _to_container(self, element):
        extra = {
            'name': element.name,
            'id': element.id,
            'meta': element.metadata._meta
        }

        container = Container(name=element.path, extra=extra, driver=self)
        return container

    def _to_obj(self, element, container):
        extra = {'path': element.path,
                 'create_time': element.create_time,
                 'last_modified': element.modify_time}
        obj = Object(name=element.name,
                     size=element.size,
                     hash=element.checksum,
                     extra=extra,
                     meta_data={},
                     container=container,
                     driver=self
                     )

        return obj
