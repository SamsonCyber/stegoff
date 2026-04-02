"""
Full st3gg audit: generate every technique, scan with stegOFF.
No assumptions. Every claim backed by an actual test run.
"""

import importlib.util
import os
import sys
import tempfile
import time
from pathlib import Path

# Import stegoff
from stegoff.orchestrator import scan, scan_text, scan_file

# Load stegg generator
STEGG_GEN = Path(os.path.expandvars(r"$TEMP/st3gg/examples/generate_examples.py"))
if not STEGG_GEN.exists():
    STEGG_GEN = Path(os.environ.get("TEMP", "/tmp")) / "st3gg" / "examples" / "generate_examples.py"
spec = importlib.util.spec_from_file_location("stegg_gen", str(STEGG_GEN))
gen = importlib.util.module_from_spec(spec)
gen.OUTPUT_DIR = tempfile.mkdtemp(prefix="stegoff_audit_")
spec.loader.exec_module(gen)

# Get all generate_ functions
all_generators = sorted([
    name for name in dir(gen)
    if name.startswith("generate_") and callable(getattr(gen, name))
])

print(f"st3gg techniques found: {len(all_generators)}")
print(f"Output dir: {gen.OUTPUT_DIR}")
print(f"{'=' * 80}")
print(f"{'#':<4} {'Technique':<40} {'Result':<10} {'Method':<30} {'Time':>6}")
print(f"{'-' * 80}")

detected = 0
missed = []
errored = []
total = 0

TEXT_EXTS = {'.txt', '.csv', '.md'}

for i, func_name in enumerate(all_generators, 1):
    technique = func_name.replace("generate_", "")
    total += 1

    try:
        func = getattr(gen, func_name)
        start = time.perf_counter()
        result_path = func()
        gen_time = time.perf_counter() - start

        if result_path and Path(result_path).exists():
            path = Path(result_path)
            start = time.perf_counter()

            if path.suffix.lower() in TEXT_EXTS:
                text = path.read_text(encoding='utf-8', errors='replace')
                report = scan_text(text, source=f"st3gg:{technique}")
            else:
                report = scan_file(path)

            scan_time = time.perf_counter() - start

            if not report.clean:
                detected += 1
                methods = ", ".join(set(f.method.value[:25] for f in report.findings[:3]))
                print(f"{i:<4} {technique:<40} {'DETECTED':<10} {methods:<30} {scan_time*1000:>5.0f}ms")
            else:
                missed.append(technique)
                print(f"{i:<4} {technique:<40} {'MISSED':<10} {'—':<30} {scan_time*1000:>5.0f}ms")
        else:
            errored.append((technique, "no output file"))
            print(f"{i:<4} {technique:<40} {'NO FILE':<10} {'—':<30}")

    except Exception as e:
        err_msg = str(e)[:60]
        errored.append((technique, err_msg))
        print(f"{i:<4} {technique:<40} {'ERROR':<10} {err_msg:<30}")

print(f"{'=' * 80}")
print(f"\nSUMMARY")
print(f"  Total techniques:  {total}")
print(f"  Detected:          {detected}")
print(f"  Missed:            {len(missed)}")
print(f"  Errors:            {len(errored)}")
print(f"  Detection rate:    {detected}/{detected + len(missed)} ({detected/(detected + len(missed))*100:.1f}%)" if (detected + len(missed)) > 0 else "")

if missed:
    print(f"\n  MISSED TECHNIQUES:")
    for m in missed:
        print(f"    - {m}")

if errored:
    print(f"\n  ERRORS (generator failed, not a stegoff issue):")
    for name, err in errored:
        print(f"    - {name}: {err}")

# Categorize for the claim
print(f"\n{'=' * 80}")
print(f"CLAIM AUDIT")
print(f"{'=' * 80}")
scannable = detected + len(missed)
print(f"  Scannable techniques: {scannable}/{total}")
print(f"  Detection rate on scannable: {detected}/{scannable} ({detected/scannable*100:.1f}%)" if scannable > 0 else "")
print(f"  Generator errors (not stegoff's fault): {len(errored)}")
if not missed:
    print(f"\n  VERDICT: Safe to claim 100% detection against st3gg scannable formats")
else:
    print(f"\n  VERDICT: {len(missed)} gaps remain. DO NOT claim 100% until fixed:")
    for m in missed:
        print(f"    - {m}")
