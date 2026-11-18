import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "run_redteam", ROOT / "defense" / "redteam" / "run_redteam.py")
rt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rt)


def test_defense_reduces_attack_success_rate():
    res = rt.run()
    off = res["baseline_off"]["asr"]
    on = res["defended_on"]["asr"]
    # baseline must be genuinely vulnerable, defended must be strictly better
    assert off > 0.0
    assert on < off
    # the defended config should neutralize the injection suite entirely here
    assert on == 0.0
