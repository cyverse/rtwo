import os

from libcloud.utils.files import read_in_chunks
from libcloud.common.types import LibcloudError
from libcloud.common.base import ConnectionUserAndKey, RawResponse
from libcloud.storage.base import Object, Container, StorageDriver

from libcloud.storage.types import ContainerIsNotEmptyError
from libcloud.storage.types import InvalidContainerNameError
from libcloud.storage.types import ContainerDoesNotExistError
from libcloud.storage.types import ObjectDoesNotExistError
from libcloud.storage.types import ObjectHashMismatchError

from irods.session import iRODSSession
from irods.models import Collection, User, DataObject
from irods.exception import DataObjectDoesNotExist, CollectionDoesNotExist

"""
iRODS data store
Requires 'pycommands' in addition to libcloud
"""


class IRODSConnection(ConnectionUserAndKey):
    """
    iRODS connection that accepts user_id and key
    """

    def __init__(self, username, password, host, port, zone, client_user=None,
                 client_zone=None, **kwargs):
        self.user_id = username
        self.key = password
        self.host = host
        self.port = port
        self.zone = zone
        if client_user:
            self.client_user = client_user
            self.client_zone = client_zone if client_zone else zone


    def connect(self, host=None, port=None, base_url=None, client_user=None,
            client_zone=None):
        if not host:
            host = self.host
        if not port:
            port = self.port
        session = iRODSSession(host=host, port=port,
                                  user=self.user_id, password=self.key,
                                  zone=self.zone, client_user=client_user,
                                  client_zone=client_zone)
        self.session = session
        return session

    def listdir(self, collection):
        """
        Expects an iRODSCollection
        """
        files = collection.data_objects
        dirs = collection.subcollections
        return (dirs, files)

    def walk(self, root_fs, topdown=True, onerror=None):
        """Directory tree generator.

        For each directory in the directory tree rooted at top (including top
        itself, but excluding '.' and '..'), yields a 3-tuple

            dirpath, dirnames, filenames
        """
        try:
            top = self.session.collections.get(root_fs)
            dirs, nondirs = self.listdir(top)
        except Exception, err:
            if onerror is not None:
                onerror(err)
            raise
            #return

        if topdown:
            yield top, dirs, nondirs
        for subcollection in dirs:
            new_path = subcollection.path
            for x in self.walk(new_path, topdown, onerror):
                yield x
        if not topdown:
            yield top, dirs, nondirs
    
class IRODSDriver(StorageDriver):
    name = 'iRODS Data Store'
    website = 'http://www.irods.org/'
    hash_type = 'md5'
    connectionCls = IRODSConnection

    def __init__(self, key, secret=None, host=None, port=None, zone=None,
                 client_user=None, client_zone=None, base_path=None, **kwargs):
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
        if not base_path:
            base_path = '/%s/home/%s' % (self.zone, self.key)
        self.base_path = base_path

        self.connection = self.connectionCls(*args,
            **self._ex_connection_class_kwargs())

        self.connection.driver = self
        self.connection.connect(client_user=client_user,
                                client_zone=client_zone)

    def iterate_containers(self):
        """
        Return a generator of containers.

        @return: A generator of Container instances.
        @rtype: C{generator} of L{Container}
        """
        base_container = self.connection.session.collections.get(self.base_path)
        if not base_container:
            raise LibcloudError(
                'Failed to retrieve containers from base container:%s' % self.base_path,
                driver=self)
        for collection in base_container.subcollections:
            yield self._to_container(collection)

    def list_containers(self):
        """
        Return a list of containers.

        @return: A list of Container instances.
        @rtype: C{list} of L{Container}
        """
        base_container = self.connection.session.collections.get(self.base_path)
        if not base_container:
            raise LibcloudError(
                'Failed to retrieve containers from base container:%s' % self.base_path,
                driver=self)
        containers = self._to_containers(base_container.subcollections)
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

    def get_container(self, container_path):
        try:
            collection = self.connection.session.collections.get(container_path)
            return self._to_container(collection)
        except CollectionDoesNotExist:
            raise ContainerDoesNotExistError(value=None,
                                             driver=self,
                                             container_name=container_path)

    def get_object(self, container_path, object_name):
        try:
            container = self.get_container(container_path)
        except CollectionDoesNotExist:
            raise ContainerDoesNotExistError(value=None, driver=self,
                                             container_name=container_path)
        try:
            obj_path = self._get_object_path(container, object_name)
            data_obj = self.connection.session.data_objects.get(obj_path)
            return self._to_obj(data_obj, container)
        except DataObjectDoesNotExist:
            raise ObjectDoesNotExistError(value=None, driver=self,
                                          object_name=object_name)


    def create_object(self, container, object_name):
        """
        Create a new object 'object_name' inside container
        """
        object_path = self._get_object_path(obj.container, obj.name)
        try:
            new_data_object = self.connection.session.data_objects.create(object_path)
            return self._to_obj(new_data_object)
        except: #CATALOG_ALREADY_HAS_ITEM_BY_THAT_NAME
            raise ObjectError(value='Object with this name already exists.'
                                    'Name must be unique among all objects '
                                    'in this container',
                              driver=self, object_name=object_name)

    def create_container(self, container_name):
        """
        Create a new container with path 'container_name'
        """
        #Containers do not end in slash
        if container_name.endswith('/'):
            container_name = container_name[:-1]

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
        #Check that download location exists
        base_name = os.path.basename(destination_path)

        if not base_name and not os.path.exists(destination_path):
            raise LibcloudError(
                value='Path %s does not exist' % (destination_path),
                driver=self)
        #Determine the file_path where file will be saved
        if not base_name:
            file_path = os.path.join(destination_path, obj.name)
        else:
            file_path = destination_path
        #Check that the object/container exists
        try:
            from_dir = obj.container.name
            collection = self.connection.session.collections.get(from_dir)
        except: #CollectionDoesNotExist
            raise LibcloudError(
                value='Container %s does not exist,' % (base_container) +
                'cannot download object to %s' % (destination_path),
                driver=self)

        if os.path.exists(file_path) and not overwrite_existing:
            raise LibcloudError(
                value='File %s already exists, but ' % (file_path) +
                'overwrite_existing=False',
                driver=self)

        with obj.extra['irods'].open('r+') as read_file:
            with open(file_path, 'w') as write_file:
                for line in read_file:
                    write_file.write(line)

    def download_object_as_stream(self, obj, chunk_size=None):
        """
        Return a generator which yields object data.

        @param obj: Object instance
        @type obj: L{Object}

        @param chunk_size: Optional chunk size (in bytes).
        @type chunk_size: C{int}

        @rtype: C{object}
        """
        #Fails with: 'iRODSDataObjectFile' object has no attr 'next'
        #with obj.extra['irods'].open('r+') as read_file:
        #    for data in read_in_chunks(read_file, chunk_size=chunk_size):
        #        yield data
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
        object_path = self._get_object_path(container, object_name)
        try:
            data_object = self.connection.session.data_objects.get(object_path)
        except DataObjectDoesNotExist:
            #Create the object
            data_object = self.connection.session.data_objects.create(object_path)

        with data_object.open('w') as f_to_write:
            with open(file_path,'r') as f_to_read:
                for line in f_to_read:
                    f_to_write.write(line)
        #Grab the newly updated object (After the write)
        data_object = self.connection.session.data_objects.get(object_path)
        return self._to_obj(data_object, container)

    def delete_object(self, obj):
        object_path = self._get_object_path(obj.container, obj.name)
        try:
            self.connection.session.data_objects.unlink(object_path)
            return True
        except DataObjectDoesNotExist:
            raise ObjectDoesNotExistError(value=None, driver=self,
                                          object_name=obj.name)


    def _get_objects(self, container):
        """
        Iterate through all data_objects on iRODS container
        """
        container_url = self._get_container_path(container)
        for root, collections, data_objects in self.connection.walk(container_url):
            for data_obj in data_objects:
                yield self._to_obj(data_obj, root)

    def _get_container_path(self, container):
        """
        Return a container path

        @param container: Container instance
        @type  container: L{Container}

        @return: A path for this container.
        @rtype: C{str}
        """
        #NOTE: Container.name contains FULL PATH
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
        name = name.replace('\\','').replace('/','').replace(' ','_')
        return name

    def _check_container_name(self, container_name):
        """
        Check if the container name is valid

        @param container_name: Container name
        @type container_name: C{str}
        """

        if ' ' in container_name:
            raise InvalidContainerNameError(value=None, driver=self,
                                            container_name=container_name)

    def _to_containers(self, subcollections):
        for collection in subcollections:
            yield self._to_container(collection)

    def _to_objs(self, obj, container):
        return [self._to_obj(element, container) for element in obj]

    def _to_container(self, irods_collection):
        extra = {
            'name': irods_collection.name,
            'path': irods_collection.path,
            'id': irods_collection.id,
            'meta': irods_collection.metadata._meta
        }

        container = Container(name=irods_collection.path, 
                              extra=extra, driver=self)
        return container

    def _to_obj(self, irods_data_obj, container):
        extra = {'path': irods_data_obj.path,
                 'create_time': irods_data_obj.create_time,
                 'irods': irods_data_obj,
                 'last_modified': irods_data_obj.modify_time}
        obj = Object(name=irods_data_obj.name,
                     size=irods_data_obj.size,
                     hash=irods_data_obj.checksum,
                     extra=extra,
                     meta_data={},
                     container=container,
                     driver=self
                     )

        return obj
