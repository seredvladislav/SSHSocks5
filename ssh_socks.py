def _ugly_helpers_import_for_future_compile():
    import logging
    import os
    import platform
    import signal
    import struct
    import sys
    import thread
    import time
    from SocketServer import ThreadingTCPServer, StreamRequestHandler
    from socket import socket, AF_INET, SOCK_STREAM

    import paramiko
    import psutil
    from multiprocessing import Process
    import argparse


if __name__ == '__main__':
    # https://github.com/pyinstaller/pyinstaller/wiki/Recipe-Multiprocessing
    import multiprocessing

    multiprocessing.freeze_support()
    from sshmproxy import main

    main()
