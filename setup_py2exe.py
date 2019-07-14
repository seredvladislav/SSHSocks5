from distutils.core import setup
import py2exe

import sys

sys.argv.append('py2exe')

py2exe_options = dict(
    excludes=[
        'FixTk', 'tcl', 'tk', '_tkinter', 'tkinter', 'Tkinter',
    ],
    includes=['cffi', ],
    # from bcrypt._bcrypt
    dll_excludes=[
        'api-ms-win-core-string-l1-1-0.dll', 'api-ms-win-core-libraryloader-l1-2-1.dll',
        'api-ms-win-eventing-classicprovider-l1-1-0.dll', 'api-ms-win-core-registry-l2-1-0.dll',
        'api-ms-win-core-profile-l1-1-0.dll', 'api-ms-win-core-localization-obsolete-l1-2-0.dll',
        'api-ms-win-core-heap-l1-1-0.dll', 'api-ms-win-eventlog-legacy-l1-1-0.dll', 'api-ms-win-core-handle-l1-1-0.dll',
        'api-ms-win-core-timezone-l1-1-0.dll', 'api-ms-win-core-kernel32-legacy-l1-1-0.dll',
        'api-ms-win-core-registry-l1-1-0.dll', 'api-ms-win-core-memory-l1-1-0.dll', 'api-ms-win-core-file-l1-1-0.dll',
        'api-ms-win-core-processthreads-l1-1-0.dll', 'api-ms-win-core-libraryloader-l1-2-0.dll',
        'api-ms-win-core-errorhandling-l1-1-0.dll', 'api-ms-win-core-perfstm-l1-1-0.dll',
        'api-ms-win-eventing-consumer-l1-1-0.dll', 'api-ms-win-core-synch-l1-2-0.dll',
        'api-ms-win-perf-legacy-l1-1-0.dll', 'api-ms-win-core-synch-l1-1-0.dll', 'api-ms-win-core-sysinfo-l1-1-0.dll',
        'api-ms-win-eventing-controller-l1-1-0.dll',
    ],
    compressed=True,
)

setup(
    name='sshmproxy', version='0.1',
    description='ssh_socks',
    author='Unknown',
    console=['ssh_socks.py'],
    options={'py2exe': py2exe_options},
    zipfile=None,
)
