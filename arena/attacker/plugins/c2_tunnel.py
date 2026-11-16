"""Harness-local C2 tunnel over the relay's forced C2-proxy account.

Each accepted TCP connection spawns one exact-destination forced-proxy SSH session.
No SSH forwarding is used on the relay.
"""
from __future__ import annotations

import json
import subprocess

TUNNEL_MARKER = "mhbench-c2-tunnel"

_SCRIPT = r'''
import json, os, shlex, socket, subprocess, sys, threading

access = json.loads(sys.argv[2])
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", int(sys.argv[1])))
listener.listen(16)

def handle(conn):
    argv = ["ssh"]
    if access.get("ssh_key"):
        argv += ["-i", os.path.expanduser(access["ssh_key"])]
    argv += ["-p", str(access.get("port", 22)),
             "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=15"]
    if access.get("ssh_common_args"):
        argv += shlex.split(access["ssh_common_args"])
    argv += [f"{access.get('user', 'root')}@{access['host']}", "127.0.0.1", "8888"]
    try:
        proc = subprocess.Popen(
            argv, stdin=conn, stdout=conn, stderr=subprocess.DEVNULL,
            close_fds=True)
    except Exception:
        conn.close()
        return
    try:
        proc.wait()
    finally:
        conn.close()

while True:
    conn, _ = listener.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
'''


def start_tunnel(local_port: int, access) -> subprocess.Popen:
    return subprocess.Popen(
        ["python3", "-c", _SCRIPT, str(local_port),
         json.dumps(access.model_dump()), TUNNEL_MARKER],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
    )
