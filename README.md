rtwo
====

A unified interface into multiple cloud providers.

Built on top of Apache libcloud with support for modern OpenStack. Also supports legacy Eucalyptus 2.x and AWS.

# Install #

pip install rtwo


## Or from source ##

```bash
pip install -e git://github.com/iPlantCollaborativeOpenSource/rtwo#egg=rtwo
```

# Use #
```python
In [1]: import rtwo

In [2]: from rtwo.provider import OSProvider

In [3]: from rtwo.identity import OSIdentity

In [4]: from rtwo.driver import OSDriver

In [5]: from rtwo.accounts.openstack import AccountDriver

In [6]: osp = OSProvider()

In [7]: ad = AccountDriver()

In [8]: ad.create_account("awesomeo")
Out[8]: 
(<User {u'email': u'awesomeo@iplantcollaborative.org', u'tenantId': u'97dfaaebb0d943baa0cfa7cbd3bf24d5', u'enabled': True, u'name': u'awesomeo', u'id': u'
3d3ca254e7054fdcaa54f473e4d5b59f'}>,
 'yourpassword',
 <Tenant {u'enabled': True, u'description': None, u'name': u'awesomeo', u'id': u'97dfaaebb0d943baa0cfa7cbd3bf24d5'}>)
In [9]: osi = OSIdentity(osp, key=OPENSTACK_ADMIN_KEY, secret=OPENSTACK_ADMIN_SECRET, user="awesomeo", auth_url="http://openstack-server.org:port/v2.0", password=ad.hashpass("awesomeo"), region_name="ValhallaRegion", ex_tenant_name="awesomeo", username="awesomeo")

In [19]: osdriver = OSDriver(osp, osi)

In [11]: sizes = osdriver.list_sizes()

In [12]: machines = osdriver.list_machines()
In [13]: osdriver.create_instance(name="Lame.", image=machines[-1], size=sizes[1])
Out[13]: <class 'rtwo.instance.OSInstance'> {'name': 'Lame.', 'ip': None, 'machine': {'alias': '7819f88b-b335-449d-b17f-ed3af350c918', 'provider': 'OpenStack', 'id': '7819f88b-b335-449d-b17f-ed3af350c918', 'name': 'Ubuntu 12.04 NoGui 4GB 64-bit bare'}, 'alias': '2b3a1021-aaed-439f-a6b6-5e6f1a9d1fd5', 'provider': 'OpenStack', 'id': '2b3a1021-aaed-439f-a6b6-5e6f1a9d1fd5', 'size': {'alias': '2', 'bandwidth': None, 'disk': 10, 'name': 'm1.small', 'price': 0.0, 'ram': 2048, 'id': 'm1.small', 'cpu': 1}}
In [14]: osdriver.list_instances()
Out[14]: [<class 'rtwo.instance.OSInstance'> {'name': 'Lame.', 'ip': None, 'machine': {'alias': '7819f88b-b335-449d-b17f-ed3af350c918', 'provider': 'OpenStack', 'id': '7819f88b-b335-449d-b17f-ed3af350c918', 'name': 'Ubuntu 12.04 NoGui 4GB 64-bit bare'}, 'alias': '2b3a1021-aaed-439f-a6b6-5e6f1a9d1fd5', 'provider': 'OpenStack', 'id': '2b3a1021-aaed-439f-a6b6-5e6f1a9d1fd5', 'size': {'alias': '2', 'bandwidth': None, 'disk': 10, 'name': 'm1.small', 'price': 0.0, 'ram': 2048, 'id': 'm1.small', 'cpu': 1}}]
```

# License

See LICENSE file.

