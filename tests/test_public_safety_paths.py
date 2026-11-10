"""Synthetic-only PCMF public installer/uninstaller path negative tests.

NEVER invokes actual install/uninstall or touches production PCMF.
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
import tempfile


def require(flag,why):
    if not flag:
        raise RuntimeError(why)


def run(validator,mode,home,app,bindir,config,data,socket,instances,env):
    return subprocess.run(
        [sys.executable,str(validator),mode,str(home),str(app),
         str(bindir),str(config),str(data),str(socket),str(instances)],
        env=env,capture_output=True,text=True,timeout=8)


def main():
    validator=Path(__file__).resolve().parents[1]/"scripts/public_safety_paths.py"
    require(validator.is_file(),"validator missing")
    failures=0;acceptances=0
    with tempfile.TemporaryDirectory(prefix="pcmf-public-paths-") as tmp:
        base=Path(tmp)
        home=base/"home";home.mkdir()
        app=home/".local/lib/pcmf"
        bindir=home/".local/bin"
        config=home/".config/pcmf"
        data=home/".local/share/pcmf"
        socket=home/".local/run/pcmf/pcmf.sock"
        instances=home/".local/share/pcmf-instances"
        env=dict(os.environ,HOME=str(home),XDG_RUNTIME_DIR=str(home/".local/run"))
        args=[home,app,bindir,config,data,socket,instances]
        def accept(mode,arr=args):
            nonlocal acceptances
            result=run(validator,mode,*arr,env)
            require(result.returncode==0,("expected pass",mode,result.stdout,result.stderr))
            acceptances+=1
        def reject(mode,arr=args,env_override=None):
            nonlocal failures
            result=run(validator,mode,*arr,env if env_override is None else env_override)
            require(result.returncode!=0 and "BLOCKED_PCMF_PATH_BOUNDARY_" in result.stderr,
                    ("expected fail closed",mode,result.stdout,result.stderr))
            failures+=1
        accept("install")
        reject("uninstall")
        app.mkdir(parents=True)
        (app/"versions"/"PCMF_LIVING_MEMORY_R17_R244-test").mkdir(parents=True)
        (app/"current").symlink_to(app/"versions"/"PCMF_LIVING_MEMORY_R17_R244-test")
        data.mkdir(parents=True)
        (data/".pcmf_root").write_text(json.dumps({"kind":"PCMF_LIVING_MEMORY_ROOT"}))
        marker=app/"installed.json"
        fixture={"active_version":"PCMF_LIVING_MEMORY_R17_R244",
                 "data_root":str(data),"socket":str(socket)}
        marker.write_text(json.dumps(fixture))
        accept("uninstall")
        accept("purge-data")
        accept("purge-all")
        def changed(index,value):
            out=args[:];out[index]=value;return out
        reject("uninstall",changed(1,Path("/")))
        reject("uninstall",changed(1,home))
        reject("uninstall",changed(1,home/".local/lib/not-pcmf"))
        reject("uninstall",changed(1,str(home)+"/.local/lib/pcmf/../"))
        reject("uninstall",changed(2,Path("/tmp")))
        reject("uninstall",changed(3,home/".config/other"))
        reject("uninstall",changed(4,Path("/etc")))
        reject("uninstall",changed(5,Path("/tmp/pcmf/pcmf.sock")))
        reject("purge-all",changed(6,home))
        reject("purge-data",changed(4,home))
        # Traversal plus symlink chains must fail even if the target is valid.
        link=home/".local/lib/pcmf-link"
        link.symlink_to(app)
        reject("uninstall",changed(1,link))
        wrong=fixture.copy();wrong["data_root"]="/tmp/other"
        marker.write_text(json.dumps(wrong))
        reject("uninstall")
        marker.write_text(json.dumps(fixture))
        (data/".pcmf_root").write_text(json.dumps({"kind":"NOT_PCMF"}))
        reject("purge-data")
        (data/".pcmf_root").write_text(json.dumps({"kind":"PCMF_LIVING_MEMORY_ROOT"}))
        marker.unlink()
        reject("uninstall")
        marker.write_text(json.dumps(fixture))
        (app/"current").unlink()
        (app/"current").symlink_to(Path("/etc"))
        reject("uninstall")
        (app/"current").unlink()
        (app/"current").symlink_to(app/"versions"/"PCMF_LIVING_MEMORY_R17_R244-test")
        env_external=dict(env,PCMF_ALLOW_EXTERNAL_DATA_ROOT="1")
        reject("purge-data",changed(4,Path("/tmp/other")),env_external)
        # Root guard only reads fixture metadata, it cannot modify a payload.
        require(json.loads(marker.read_text())==fixture,
                "validator unexpectedly mutated installed marker")
    print(json.dumps({"status":"PASS_PUBLIC_PCMF_PATH_BOUNDARY",
                      "acceptances":acceptances,"rejections":failures,
                      "production_files_touched":False},sort_keys=True))


if __name__=="__main__":
    try:
        main()
    except Exception as exc:
        print("FAIL_PUBLIC_PCMF_PATH_BOUNDARY",str(exc),file=sys.stderr)
        sys.exit(1)
