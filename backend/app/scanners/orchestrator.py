from concurrent.futures import ThreadPoolExecutor, as_completed
from app.scanners.nmap_scanner import run_nmap
from app.scanners.subdomain_scanner import run_subdomain_scan
from app.scanners.tech_detector import run_tech_detection
from app.scanners.nuclei_scanner import run_nuclei
import json
import time

def safe_run_nmap(target):
    start = time.time()
    try:
        result = run_nmap(target)
    except Exception as e:
        result = {"error": True, "message": str(e)}
    print(f"[timing] nmap: {time.time() - start:.1f}s")
    return result

def safe_run_nuclei(target, concurrency=50):
    start = time.time()
    try:
        result = run_nuclei(target, concurrency=concurrency)
    except Exception as e:
        result = {"error": True, "message": str(e)}
    print(f"[timing] nuclei ({target}): {time.time() - start:.1f}s")
    return result

def safe_run_subdomain_scan(target):
    start = time.time()
    try:
        result = run_subdomain_scan(target)
    except Exception as e:
        result = {"error": True, "message": str(e)}
    print(f"[timing] subdomain: {time.time() - start:.1f}s")
    return result

def safe_run_tech_detection(target):
    start = time.time()
    try:
        result = run_tech_detection(target)
    except Exception as e:
        result = {"error": True, "message": str(e)}
    print(f"[timing] tech_detection ({target}): {time.time() - start:.1f}s")
    return result


def run_full_recon(target, on_module_done=None):
    results = {}

    with ThreadPoolExecutor(max_workers=6) as executor:
        future_nmap = executor.submit(safe_run_nmap, target)
        future_nuclei_juice = executor.submit(safe_run_nuclei, "http://127.0.0.1:3000", 50)
        future_nuclei_dvwa = executor.submit(safe_run_nuclei, "http://127.0.0.1:8081", 10)
        future_subdomain = executor.submit(safe_run_subdomain_scan, target)
        future_tech_juice = executor.submit(safe_run_tech_detection, "localhost:3000")
        future_tech_dvwa = executor.submit(safe_run_tech_detection, "localhost:8081")

        future_to_name = {
            future_nmap: "nmap",
            future_nuclei_juice: "nuclei_juice",
            future_nuclei_dvwa: "nuclei_dvwa",
            future_subdomain: "subdomains",
            future_tech_juice: "tech_juice",
            future_tech_dvwa: "tech_dvwa",
        }

        for future in as_completed(future_to_name):
            name = future_to_name[future]
            results[name] = future.result()

            if on_module_done:
                on_module_done(name)

    return {
        "nmap": results["nmap"],
        "subdomains": results["subdomains"],
        "technologies": {
            "juice_shop": results["tech_juice"],
            "dvwa": results["tech_dvwa"],
        },
        "nuclei": {
            "nuclei_juice": results["nuclei_juice"],
            "nuclei_dvwa": results["nuclei_dvwa"],
        },
    }


if __name__ == "__main__":
    print(json.dumps(run_full_recon("127.0.0.1"), indent=2, ensure_ascii=False))