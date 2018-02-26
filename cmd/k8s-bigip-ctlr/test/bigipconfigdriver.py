#!/usr/bin/env python

import signal
import socket
import sys

def signal_handler(signal, frame):
    sys.stderr.write("WARNING: Received signal"+ str(signal))
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("", 0))
s.listen(5)
while 1:
    try:
        sys.stderr.write("DEBUG: Python Driver listening")
        client, address = s.accept()
    except KeyboardInterrupt:
        sys.exit(0)
