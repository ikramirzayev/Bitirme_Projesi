import os
import json
import subprocess
import uuid

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))


def parse_nuclei_jsonl(jsonl_file):
    findings = []
    if not os.path.exists(jsonl_file):
        return findings

    with open(jsonl_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            veri = json.loads(line)
            findings.append({
                "template_id": veri.get("template-id"),
                "name": veri.get("info", {}).get("name"),
                "severity": veri.get("info", {}).get("severity"),
                "matched_at": veri.get("matched-at"),
            })
    return findings


def run_nuclei(target, concurrency=50, tags=None):
    output_file = os.path.join(CURRENT_DIR, f"nuclei_output_{uuid.uuid4().hex}.jsonl")
    tags_to_use = tags or "exposure,misconfig,default-login,xss,sqli,takeover,config,backup,debug"

    result = subprocess.run(
        [
            "nuclei",
            "-u", target,
            "-ni",
            "-mhe", "0",
            "-c", str(concurrency),
            "-rl", "500",
            "-timeout", "3",
            "-tags", tags_to_use,
            "-severity", "low,medium,high,critical",
            "-jsonl",
            "-o", output_file,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    if result.returncode != 0:
        return {
            "error": True,
            "message": "Nuclei calisirken bir hata olustu.",
            "stderr": result.stderr,
        }

    findings = parse_nuclei_jsonl(output_file)

    if os.path.exists(output_file):
        os.remove(output_file)

    return {
        "target": target,
        "findings": findings,
        "count": len(findings),
    }


if __name__ == "__main__":
    print(json.dumps(run_nuclei("http://127.0.0.1:3000"), indent=2, ensure_ascii=False))