#!/usr/bin/env python

import argparse
import os
import signal
import socket
import sys

# Parses the command line arguments
parser = argparse.ArgumentParser(description='Writes to a temporary file.')
# This argument is required by this file. It provides name for the tmp file.
parser.add_argument('--config-file', type=str, required=True)
parser.add_argument('--ctlr-prefix', type=str)
args = parser.parse_args()

# Establishes signal handler for the kill -2 command
def signal_handler(signal, frame):
    sys.stderr.write("WARNING: Received signal"+ str(signal))
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Opens a socket to stall in the while loop
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("", 0))
s.listen(5)

# Creates the tmp file
scriptDir = os.path.dirname(__file__)
filePath = os.path.join(scriptDir, args.config_file)
f = open(filePath,"w+")

# Infinite loop waiting for SIGINT
while 1:
    try:
        sys.stderr.write("DEBUG: Python Driver listening\n")
        f.write("Ready for KeyboardInterrupt")
        f.close()
        client, address = s.accept()
    except KeyboardInterrupt:
        sys.exit(0)
