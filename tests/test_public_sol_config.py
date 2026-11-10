"""Public Sol client rejects unconfigured owner credentials/profile."""
import importlib.util
import json
import os
from pathlib import Path
import sys


def main():
    script=Path(__file__).resolve().parents[1]/"integrations/sol/app/pcmf_client.py"
    assert script.is_file()
    for name in ("SOL_PCMF_CLIENT_KEY","SOL_PCMF_PROFILE"):
        os.environ.pop(name,None)
    spec=importlib.util.spec_from_file_location("pcmf_public_sol_client",script)
    module=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=module
    spec.loader.exec_module(module)
    tests=0
    def blocked(kwargs,reason):
        nonlocal tests
        try:
            module.PcmfClient(**kwargs)
        except module.PcmfClientError as e:
            assert str(e)==reason,(str(e),reason)
            tests+=1
        else:
            raise AssertionError("missing required public client configuration accepted")
    blocked({},"pcmf_client_key_not_configured")
    blocked({"key_path":Path("/nonexistent/test-only-key")},"pcmf_profile_not_configured")
    c=module.PcmfClient(
        key_path=Path("/nonexistent/test-only-key"),
        profile="synthetic_profile",
        writes_requested=False)
    assert c.profile=="synthetic_profile"
    assert c.writes_requested is False
    try:
        c._key()
    except module.PcmfClientError as e:
        assert str(e)=="pcmf_client_key_unavailable"
        tests+=1
    else:
        raise AssertionError("missing file was accepted as a client credential")
    print(json.dumps({"status":"PASS_PUBLIC_SOL_FAIL_CLOSED_CONFIG",
                      "checks":tests,"private_key_read":False,
                      "production_memory_used":False},sort_keys=True))

if __name__=="__main__":
    main()
