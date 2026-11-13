"""One-shot deterministic R12 72-hour expiry sweep, for a user systemd timer.

The exact canonical root ID is pinned in an owner-controlled 0600 config file.
This utility modifies only the isolated encrypted deferred inbox, never PCMF.
"""
import argparse
import json
import os
import stat
import sys
from pathlib import Path
from deferred_queue_r12 import DeferredQueue,QueueError,TTL_SECONDS

def load_config(path):
    path=Path(path)
    st=path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077:
        raise QueueError("INSECURE_QUEUE_CONFIG")
    data=json.loads(path.read_text())
    if set(data)!={"directory","root_id","enabled","version"} or data["version"]!="PCMF_R12_QUEUE_GC_CONFIG_V1":
        raise QueueError("INVALID_QUEUE_CONFIG")
    if data["enabled"] is not True:
        raise QueueError("QUEUE_GC_NOT_AUTHORIZED")
    directory=Path(data["directory"])
    if not directory.is_absolute() or directory.is_symlink():
        raise QueueError("UNSAFE_QUEUE_DIRECTORY")
    return DeferredQueue(directory,data["root_id"])

def main(argv=None):
    ap=argparse.ArgumentParser(description="Sweep expired local encrypted notes (never native PCMF reject).")
    ap.add_argument("--config",required=True)
    args=ap.parse_args(argv)
    try:
        q=load_config(args.config)
        result=q.sweep()
        # Metadata-only output; no tokens, notes, passwords or key material.
        print(json.dumps({"status":"PASS" if result["errors"]==0 else "INCOMPLETE",
                          "expired":result["expired_local_only"],
                          "errors":result["errors"],"ttl_seconds":TTL_SECONDS,
                          "canonical_pcmf_modified":False},sort_keys=True))
        return 0 if result["errors"]==0 else 3
    except (QueueError,OSError,ValueError) as exc:
        print("QUEUE_GC_BLOCKED="+type(exc).__name__,file=sys.stderr)
        return 2

if __name__=="__main__":
    sys.exit(main())
