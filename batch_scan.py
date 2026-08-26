"""
Batch-scan every .apk in a directory from the command line.

Usage:
    python batch_scan.py /path/to/apks/ --vt-key YOUR_VT_KEY --out results.json
    python batch_scan.py /path/to/apks/ --no-vt              # skip Layer 1
"""

import argparse
import json
import os
import sys
import time

from modules.pipeline import scan_apk


def main():
    parser = argparse.ArgumentParser(description="Batch-scan a folder of APKs with OneClick.")
    parser.add_argument("directory", help="Folder containing .apk files")
    parser.add_argument("--vt-key", default=None, help="VirusTotal API key (optional)")
    parser.add_argument("--no-advanced", action="store_true", help="Skip advanced static analysis (faster)")
    parser.add_argument("--out", default="batch_results.json", help="Output JSON path")
    args = parser.parse_args()

    apk_files = [
        os.path.join(args.directory, f)
        for f in sorted(os.listdir(args.directory))
        if f.lower().endswith(".apk")
    ]

    if not apk_files:
        print(f"No .apk files found in {args.directory}")
        sys.exit(1)

    print(f"Found {len(apk_files)} APK(s). Starting batch scan...\n")

    results = []
    for i, path in enumerate(apk_files, 1):
        filename = os.path.basename(path)
        print(f"[{i}/{len(apk_files)}] Scanning {filename} ...", end=" ", flush=True)
        start = time.time()
        try:
            result = scan_apk(
                path, filename,
                vt_api_key=args.vt_key,
                run_advanced=not args.no_advanced,
            )
            elapsed = time.time() - start

            if result.get("known_threat"):
                verdict = "KNOWN THREAT (VirusTotal)"
            elif result.get("error"):
                verdict = f"ERROR: {result['error']}"
            else:
                ml = result.get("ml_result", {})
                verdict = f"{ml.get('label', '?')} ({ml.get('risk_score', '?')}%)"

            print(f"{verdict}  [{elapsed:.1f}s]")
            results.append({"file": filename, "path": path, **result})

        except Exception as e:
            print(f"FAILED: {e}")
            results.append({"file": filename, "path": path, "error": str(e)})

    with open(args.out, "w") as f:
        json.dump(results, f, indent=2, default=str)

    malicious = sum(1 for r in results if r.get("known_threat") or
                     (r.get("ml_result") or {}).get("label") == "Malicious")
    suspicious = sum(1 for r in results if (r.get("ml_result") or {}).get("label") == "Suspicious")
    safe = sum(1 for r in results if (r.get("ml_result") or {}).get("label") == "Safe")

    print(f"\n{'='*50}")
    print(f"Batch scan complete: {len(results)} files")
    print(f"  Malicious:  {malicious}")
    print(f"  Suspicious: {suspicious}")
    print(f"  Safe:       {safe}")
    print(f"Full results written to {args.out}")


if __name__ == "__main__":
    main()
