"""Optional runtime checks for the OpenShell application image."""
import os
from pathlib import Path
import subprocess

import pytest


IMAGE = os.environ.get("SIO2_OPENSHELL_IMAGE")
pytestmark = pytest.mark.skipif(not IMAGE, reason="Set SIO2_OPENSHELL_IMAGE to test the built application image.")


SMOKE = r'''
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import subprocess

from sio2.config import load_config
from sio2.tools.scan import run_bandit
from sio2.utils import target_commit
from sio2.workspace import Workspace

assert os.getuid() == 1500
assert Path.cwd() == Path('/sandbox')
assert shutil.which('ip')
assert shutil.which('nft')
assert shutil.which('docker') is None
assert importlib.metadata.version('bandit') == '1.9.4'
assert not Path('/opt/sio2/.env').exists()
assert not os.access('/opt/sio2/src', os.W_OK)
assert not Path('/opt/targets').exists()
root = Path('/inputs/target')
case = root / 'testcode/BenchmarkTest00001.py'
original = case.read_bytes()
assert not os.access(case, os.W_OK)
assert target_commit(root) == 'f1291485808b66e20ddb6b01b10dc71b3df8c8ba'
cfg = load_config(Path('/opt/sio2/configs/owasp-full.toml'))
with Workspace(root, cfg.target) as ws:
    findings = run_bandit(ws.root, cfg.scan, cfg.target)
    assert findings['version'] == '1.9.4'
    assert findings['alerts']
    assert not findings['bandit_errors']
    assert not (ws.root / '.git').exists()
    assert not list(ws.root.glob('expectedresults*.csv'))
assert case.read_bytes() == original
Path('/sandbox/result.txt').write_text('writable output')
subprocess.run(['sio2', '--help'], check=True, capture_output=True)
print(json.dumps({'alerts': len(findings['alerts']), 'target_commit': target_commit(root)}))
'''


def test_openshell_image_scans_a_read_only_runtime_target():
    target = Path(__file__).parents[1] / "targets/owasp-benchmark-python"
    assert target.is_dir(), "Clone the README's pinned OWASP target before this integration test."
    result = subprocess.run([
        "docker", "run", "--rm", "--pull=never", "--network=none", "--read-only",
        "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=128", "--memory=1g",
        "--mount", f"type=bind,src={target.resolve()},dst=/inputs/target,readonly",
        "--tmpfs", "/sandbox:rw,uid=1500,gid=1500,mode=0755,size=32m",
        "--tmpfs", "/tmp:rw,mode=1777,size=128m", IMAGE, "python", "-c", SMOKE,
    ], capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    assert '"target_commit": "f1291485808b66e20ddb6b01b10dc71b3df8c8ba"' in result.stdout
