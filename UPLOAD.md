How To Upload A New Version of rtwo
====

Uploading a new version of rtwo to the pypi can be tough. Here are some pointers.

# pip install twine and wheel #

pip install twine wheel

# Keybase is required && YOU CAN NOT USE THE ROOT USER! #

## Installing keybase.io
- To install Keybase cli For linux: https://keybase.io/docs/the_app/install_linux
- Keybase account/password is not covered 
- Local account creation is not covered (But you cannot use root to run the keybase cli)

NOTE: If you are getting "permissions denied" errors in keybase, like this:
```
$ run_keybase
mkdir: cannot create directory '/run/user/0': Permission denied

# be sure to *Unset* this variable:
$ unset XDG_RUNTIME_DIR
```
NOTE 2: Additionally, you may find that your log files are owned by root, if thats the case, go ahead and chown:
```
## Provisioning a new keybase device on first login
```
The device you are currently using needs to be provisioned.
Which one of your existing devices would you like to use
to provision this new device?

        1. [computer]   mickey-cyverse-vm-1
        2. [paper key]  regret sauce
        3. I don't have access to any of these devices.

Choose a device: 1


************************************************************
* Name your new device!                                    *
************************************************************



Enter a public name for this device: cdosborn-vagrant-boi


Type this verification code into your other device:

        sell peanut fly code trap tenant cattle

If you are using the command line client on your other device, run this command:

        keybase device add

It will then prompt you for the verification code above.




✔ Success! You provisioned your device cdosborn-vagrant-boi.

You are logged in as KEYBASE_USERNAME
  - type `keybase help` for more info.
```

## On an already-provisioned device:
```
keybase device add
▶ INFO Forking background server with pid=10310
Starting `device add`...

(Please note that you should run `device add` on a computer that is
already registered with Keybase)
What kind of device are you adding?

(1) Desktop or laptop
(2) Mobile phone

Choose a device type: 1

Enter the verification code from your other device here.  To get
a verification code, run 'keybase login' on your other device.

Verification code: sell peanut fly code trap tenant cattle


✔ Verification code received.



✔ Success! You added a new device named cdosborn-vagrant-boi to your account.
```

$ sudo chown -R vagrant:vagrant  /home/vagrant/.cache/keybase/
```
# But First, Update the Version! #

Updating the version is CRITICAL when you make changes, because other projects may depend on specific solutions from older versions of rtwo.


Edit the `rtwo/version.py` module and change the appropriate integer in the `VERSION` line to reflect the changes made.

```python
VERSION = (major_change, minor_change, patch_change, 'dev', 0)
```

# Create New Distributables #
```bash
python setup.py sdist bdist_wheel upload --sign
# gpg --no-use-agent --detach-sign -a rtwo-$VERSION-py2-none-any.whl (will be called by entering the line above)
# < Enter your Keybase password to sign>
# < After signing, your file will be uploaded, and you will get a 200, 500, or 4xx status indicating success/failure.
# (Note that on occasion, a 500 is a 200)
# gpg --no-use-agent --detach-sign -a rtwo-$VERSION.tar.gz (will be called by entering the line above)
# < Enter your Keybase password to sign>
# < After signing, your file will be uploaded, and you will get a 200, 500, or 4xx status indicating success/failure.
# (Note that on occasion, a 500 is a 200)
```

# Upload packages (PYPI login required) #
```bash
twine upload dist/*
# No longer need these files after uploading
rm dist/rtwo-$VERSION
```

# Installing New Version On Dependant Machines #
```bash
pip install rtwo==$VERSION
```
# More Information #

See links below:
* https://keybase.io/docs/command_line
