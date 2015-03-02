HOW TO UPLOAD A VERSION OF RTWO
====

Uploading a new version of rtwo to the pypi can be tough. Here are some pointers.

NOTE: This assumes you have already gone to 'keybase.io', created an account, installed the keybase CLI and executed keybase login. If you haven't done this, you probably should.

# Update the Version #

Updating the version is CRITICAL when you make changes, because other projects may depend on specific solutions from older versions of rtwo.


Edit the `rtwo/version.py` module and change the appropriate integer in the `VERSION` line to reflect the changes made.

```python
VERSION = (major_change, minor_change, patch_change, 'dev', 0)
```

# Create .whl and .tar.gz #
```bash
python setup.py sdist bdist_wheel
```

# Sign packages (KEYBASE login required) #
```bash
cd dist/
gpg --no-use-agent --detach-sign -a rtwo-$VERSION-py2-none-any.whl
gpg --no-use-agent --detach-sign -a rtwo-$VERSION.tar.gz
cd ..
```

# Upload packages (PYPI login required) #
```bash
twine upload dist/*
# No longer need these files after uploading
rm dist/rtwo-$VERSION
```

# Installing on dependant machines #
```bash
pip install rtwo==$VERSION
```
# More Information #

See links below:
* https://keybase.io/docs/command_line
