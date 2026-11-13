import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from deferred_queue_r12 import DeferredQueue,TTL_SECONDS
from queue_gc_r12 import load_config,main
ROOT="b"*32
TOKEN="a"*64
NOTE="Synthetic expiring memory note for testing."
PASS="an-example-private-passphrase"

class Clock:
    def __init__(self):self.value=1_800_000_000
    def __call__(self):return self.value

class TestGCRunner(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory(prefix="pcmf-r12-gc-")
        self.addCleanup(tmp.cleanup)
        self.base=Path(tmp.name)
        self.path=self.base/"queue"
        self.clock=Clock()
        self.q=DeferredQueue(self.path,ROOT,now=self.clock)
        self.q.create_owner_keys(PASS,PASS)
        self.config=self.base/"gc.json"
        self.record={"version":"PCMF_R12_QUEUE_GC_CONFIG_V1","directory":str(self.path),
                     "root_id":ROOT,"enabled":True}
        self._write()
    def _write(self):
        self.config.write_text(json.dumps(self.record))
        self.config.chmod(0o600)
    def add(self):
        return self.q.enqueue(TOKEN,NOTE,
            lambda t:{"status":"pending","token":TOKEN,"root_id":ROOT,
                "note_hash":hashlib.sha256(NOTE.encode()).hexdigest(),
                "note_bytes":len(NOTE.encode())},owner_capture_enabled=True)
    def test_enabled_private_config(self):
        self.assertEqual(load_config(self.config).root_id,ROOT)
    def test_disabled_config_refused(self):
        self.record["enabled"]=False
        self._write()
        self.assertEqual(main(["--config",str(self.config)]),2)
    def test_insecure_config_refused(self):
        self.config.chmod(0o644)
        self.assertEqual(main(["--config",str(self.config)]),2)
    def test_plaintext_not_printed(self):
        self.add()
        self.clock.value += TTL_SECONDS
        with patch("time.time",return_value=self.clock.value),patch("builtins.print") as p:
            self.assertEqual(main(["--config",str(self.config)]),0)
        output="".join(str(x) for call in p.call_args_list for x in call.args)
        self.assertNotIn(NOTE,output)
        self.assertNotIn(TOKEN,output)
        self.assertFalse((self.path/"notes"/(TOKEN+".json")).exists())
    def test_nonexpired_preserved(self):
        self.add()
        with patch("time.time",return_value=self.clock.value+TTL_SECONDS-1):
            self.assertEqual(main(["--config",str(self.config)]),0)
        self.assertTrue((self.path/"notes"/(TOKEN+".json")).exists())
    def test_no_live_root_reference_in_gc(self):
        script=(Path(__file__).parent/"queue_gc_r12.py").read_text()
        self.assertNotIn("subprocess",script.lower())
        self.assertNotIn("pcmf"," ".join(x.strip() for x in script.splitlines() if x.strip().startswith(("import subprocess","from pcmf"))))
        self.assertNotIn("/media/"+"morphius/",script)
if __name__=="__main__":unittest.main()
