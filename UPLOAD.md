How To Upload A New Version of rtwo
====

## Update the Version
Edit the `rtwo/version.py` module and change the appropriate integer in the `VERSION` line to reflect the changes made.

```python
VERSION = (major_change, minor_change, patch_change, 'dev', 0)
```

## Create the distributables
In the `setup.py` command sdist results in tarball, and bdist_wheel a wheel file.
```bash
pip install -r requirements.txt
python setup.py sdist bdist_wheel
```

## Upload packages (PYPI login required)
```bash
pip install twine
twine upload <path to tar.gz> <path to .whl>
```
