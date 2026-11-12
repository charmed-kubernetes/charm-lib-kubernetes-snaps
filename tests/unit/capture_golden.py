"""Capture `golden_0_0_1.json` from the published 0.0.1 wheel.

Not run by pytest. The fixture must come from the published wheel, never from the
code under test:

    uvx --from pip pip download "charms.kubernetes-snaps==0.0.1" --no-deps -d /tmp/old
    python -m zipfile -e /tmp/old/charms_kubernetes_snaps-0.0.1-py3-none-any.whl /tmp/old/pkg
    cd /tmp && PYTHONPATH=/tmp/old/pkg python <repo>/tests/unit/capture_golden.py \
        <repo>/tests/unit/golden_0_0_1.json

Run it outside the repository so the working tree's `charms/` does not shadow the
wheel. The PyYAML version is recorded because `yaml.dump` output can differ between
versions.
"""

import json
import sys
import tempfile
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent))
import golden_scenario

from charms import kubernetes_snaps

with tempfile.TemporaryDirectory() as tmp:
    result = golden_scenario.run(kubernetes_snaps, Path(tmp))
result["captured_from"] = "charms.kubernetes-snaps 0.0.1"
result["pyyaml"] = yaml.__version__
Path(sys.argv[1]).write_text(json.dumps(result, indent=1, sort_keys=True) + "\n")
print("wrote", sys.argv[1], "from", kubernetes_snaps.__file__)
