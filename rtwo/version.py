"""
rtwo version.
"""
from subprocess import Popen, PIPE
from os.path import abspath, dirname

VERSION = (0, 1, 9, 'dev', 0)

git_match = "(?P<opt_editable_flag>-e )?"\
            "(?P<git_flag>git\+[a-z]+://)\S*/(?P<repo_name>.*)\.git"\
            "(?P<opt_egg_flag>#egg=)?(?P<egg>[a-zA-Z0-9-]*[a-zA-Z])?"\
            "(?P<opt_version_flag>-)?(?P<opt_version>[0-9][0-9.-]*[0-9])?(?P<dev_flag>-dev)?"

            # Version is optional
egg_match = "(?P<egg>\S.*[a-zA-Z])"\
            "(?P<opt_version_flag>[-=]+)?"\
            "(?P<opt_version>[0-9]*[0-9.-]*[0-9])?(?P<dev_flag>-dev)?"
            # Version is optional
def read_requirements(requirements_file):
    """
    Requirements files use two specific formats:
    packagename[==1.3.1]
    and
    [-e ]git+[http/https/git]://github.com/abc/xyz.git[#egg=packagename[-1.3.1]]

    This function converts git to the bottom format
    and
    includes them as a dependency_link for setup.py
    """
    import re
    dependencies = []
    install_requires = []
    egg_regex = re.compile(egg_match)
    git_regex = re.compile(git_match)
    with open(requirements_file, 'r') as f:
        for line in f.read().split('\n'):
            #Skip empty spaces
            if not line:
                continue
            #Read the line for version info
            r = git_regex.search(line)
            if not r:
                r = egg_regex.search(line)
            if not r:
                print 'Failed to identify requirement:%s' % line
                continue
            group = r.groupdict()
            if not group:
                continue
            if group.get('git_flag'):
                dependencies.append(line)
            #Add a version-specific requirement
            if group.get('opt_version') and group.get('egg'):
                install_requires.append("%s==%s%s" % (group['egg'], group['opt_version'],
                        '-dev' if group.get('dev_flag') else ''))
            #Add a generic egg requirement
            elif group.get('egg'):
                install_requires.append("%s" % (group['egg']))
            #Infer generic egg requirement from dependency missing #egg=
            elif group.get('repo_name'):
                install_requires.append("%s" % (group['repo_name']))
    return (dependencies, install_requires)


def write_requirements(requirements_file, new_file):
    (dependencies, install_requires) = read_requirements(requirements_file)
    with open(new_file,'w') as write_to:
        write_to.write("#Dependencies:\n")
        [write_to.write("%s\n" % line) for line in dependencies]
        write_to.write("#Requirements:\n")
        [write_to.write("%s\n" % line) for line in install_requires]
    return
        
def git_sha():
    loc = abspath(dirname(__file__))
    try:
        p = Popen(
            "cd \"%s\" && git log -1 --format=format:%%h" % loc,
            shell=True,
            stdout=PIPE,
            stderr=PIPE
        )
        return p.communicate()[0]
    except OSError:
        return None

def get_version(form='short'):
    """
    Returns the version string.

    Takes single argument ``form``, which should be one of the following
    strings:
    
    * ``short`` Returns major + minor branch version string with the format of
    B.b.t.
    * ``normal`` Returns human readable version string with the format of 
    B.b.t _type type_num.
    * ``verbose`` Returns a verbose version string with the format of
    B.b.t _type type_num@git_sha
    * ``all`` Returns a dict of all versions.
    """
    versions = {}
    branch = "%s.%s" % (VERSION[0], VERSION[1])
    tertiary = VERSION[2]
    type_ = VERSION[3]
    type_num = VERSION[4]
    
    versions["branch"] = branch
    v = versions["branch"]
    if tertiary:
        versions["tertiary"] = "." + str(tertiary)
        v += versions["tertiary"]
    versions['short'] = v
    if form is "short":
        return v
    v += " " + type_ + " " + str(type_num)
    versions["normal"] = v
    if form is "normal":
        return v
    v += " @" + git_sha()
    versions["verbose"] = v
    if form is "verbose":
        return v
    if form is "all":
        return versions

