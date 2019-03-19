# BSD 3-Clause License
#
# Copyright (c) 2019, k4m1
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import socket
import sys
import threading
import select

global recving
global sending
global running

running = None
recving = None
sending = None


# Sane version of print() for network
def printf(msg):
    sys.stdout.write(msg)
    sys.stdout.flush()


# Returns descriptor to new process.
# This should be multi-platform supported for windows-fags *shrugs*
def fork(fun, argv):
    desc = threading.Thread(target=fun, args=(argv,))
    desc.start()
    return desc


# connects to host:port.
# Return None on error or socket descriptor on success
def connect(host, port):
    sock_fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock_fd.connect((host, port))
        sock_fd.setblocking(0)
    except Exception as Err:
        printf(Err)
        sock_fd = None
    finally:
        return sock_fd


# Function that just listens for messages from server
# and prints them out
#
# Do note that even if python threading supports simultanious send()+recv(),
# socket can never send and recv at same time.
def receiver(sock_fd):
    global recving
    while running:
        if not sending:
            recving = 1
            rd = select.select([sock_fd], [], [], 1)
            if rd[0]:
                data = sock_fd.recv(4096)
                data = data.decode("utf-8")
                printf(data)
            recving = None


# Read comments above
def sender(sock_fd):
    global sending
    global running
    while running:
        data = None
        sending = None
        try:
            data = input("")
            data += "\r\n"
            data = data.encode()
        except KeyboardInterrupt:
            running = None
        if data:
            sending = True
            while recving:
                # Wait until we've finished receiving data
                continue
            # send data
            sock_fd.send(data)
            sending = None


def usage():
    print("/path/to/nc.py <host> <port>")
    return -1


def main(argc, argv):
    global running
    # Add support for more arguments if you wish, I'm lazy
    if argc != 3:
        return usage()

    try:
        sock_fd = connect(argv[1], int(argv[2]))
    except Exception as Err:
        printf(Err)
        return usage()
    running = 1
    fork(receiver, sock_fd)
    sender(sock_fd)
    return 0


if __name__ == "__main__":
    sys.exit(main(len(sys.argv), sys.argv))
