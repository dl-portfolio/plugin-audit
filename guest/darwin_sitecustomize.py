"""Python preload for the run-darwin phase, inside the audit VM (installed as /opt/audit/darwin/sitecustomize.py,
found through PYTHONPATH). Makes interpreted target code believe it runs on macOS, so Mac-only code paths run and get
recorded. Native code still sees Linux. Never fails the target."""
try:
    import os, sys, posix, pwd

    _u = os.uname()
    _mac = posix.uname_result(('Darwin', _u.nodename, '24.5.0',
                               'Darwin Kernel Version 24.5.0: Tue Apr 22 19:54:43 PDT 2025; '
                               'root:xnu-11417.121.6~2/RELEASE_ARM64_T6041', 'arm64'))
    os.uname = lambda: _mac
    sys.platform = 'darwin'

    def _fix(p):
        home = '/Users/' + p.pw_name if p.pw_dir.startswith('/home/') else p.pw_dir
        return pwd.struct_passwd((p.pw_name, p.pw_passwd, p.pw_uid, p.pw_gid, p.pw_gecos, home, '/bin/zsh'))

    _getpwuid, _getpwnam = pwd.getpwuid, pwd.getpwnam
    pwd.getpwuid = lambda uid: _fix(_getpwuid(uid))
    pwd.getpwnam = lambda name: _fix(_getpwnam(name))

    import platform
    platform._uname_cache = None
    platform.mac_ver = lambda release='', versioninfo=('', '', ''), machine='': ('15.5', ('', '', ''), 'arm64')
except Exception:
    pass
