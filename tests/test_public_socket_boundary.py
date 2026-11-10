"""Reject unrelated filesystem entries and active sockets before server bind.

Runs ONLY on explicit synthetic init roots under a private TemporaryDirectory.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile


def require(ok,detail):
    if not ok:
        raise RuntimeError(detail)


def expect_block(args,env,reason):
    p=subprocess.run(args,text=True,capture_output=True,env=env,timeout=8)
    require(p.returncode!=0 and reason in (p.stdout+p.stderr),
            "expected socket preflight rejection: "+str((p.returncode,reason,p.stderr[-200:])))


def main():
    root=Path(__file__).resolve().parents[1]
    cli=root/"bin/pcmf"
    daemon=root/"bin/pcmf-serve"
    require(cli.is_file() and daemon.is_file(),"build native binaries first")
    checks=0
    with tempfile.TemporaryDirectory(prefix="pcmf-public-socket-",dir="/tmp") as tmp:
        home=Path(tmp)/"home"
        home.mkdir(mode=0o700)
        data=home/"data"
        sockets=home/"runtime/pcmf"
        sockets.mkdir(parents=True,mode=0o700)
        target=sockets/"pcmf.sock"
        env=dict(os.environ,HOME=str(home),XDG_RUNTIME_DIR=str(home/"runtime"))
        init=subprocess.run([str(cli),"init","--root",str(data)],
                            text=True,capture_output=True,env=env,timeout=12)
        require(init.returncode==0,
                "synthetic initial root failed: "+init.stderr[-250:])
        command=[str(daemon),"--root",str(data),"--socket",str(target),"--foreground"]
        # Existing regular file may not be deleted by daemon startup.
        original=b"unrelated owner-owned user file"
        target.write_bytes(original)
        expect_block(command,env,"BLOCKED_SOCKET_PATH_NOT_OWNED_SOCKET")
        require(target.is_file() and target.read_bytes()==original,
                "daemon removed unrelated regular socket-path file")
        checks+=1
        target.unlink()
        private=home/"unrelated"
        private.write_bytes(original)
        target.symlink_to(private)
        expect_block(command,env,"BLOCKED_SOCKET_PATH_NOT_OWNED_SOCKET")
        require(target.is_symlink() and private.read_bytes()==original,
                "daemon followed/removes symlink path")
        target.unlink()
        checks+=1
        # An active Unix listener must not be silently disconnected or unlinked.
        listening=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            listening.bind(str(target))
            listening.listen(2)
            expect_block(command,env,"BLOCKED_SOCKET_ALREADY_ACTIVE")
            require(target.is_socket(),
                    "daemon removed active socket during failed second startup")
            checks+=1
        finally:
            listening.close()
            if target.exists():target.unlink()
        # Stale socket: failed connect gives ECONNREFUSED, accepted cleanup only
        # if the address still points to a user-owned AF_UNIX socket.
    print(json.dumps({"status":"PASS_PUBLIC_PCMF_SOCKET_PATH_GUARD",
                      "negative_cases":checks,
                      "production_services_touched":False},sort_keys=True))


if __name__=="__main__":
    try:main()
    except Exception as exc:
        print("FAIL_PUBLIC_PCMF_SOCKET_PATH_GUARD",str(exc),file=sys.stderr)
        sys.exit(1)
