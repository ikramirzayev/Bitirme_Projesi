import os
import time
import threading
import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY")  # yoksa None - sorun degil, sadece yavas calisir

# Anahtarsiz: 30 saniyede 5 istek siniri -> istekler arasi min 6.5 saniye
# Anahtarli: 30 saniyede 50 istek siniri -> istekler arasi min 0.7 saniye
MIN_INTERVAL = 0.7 if NVD_API_KEY else 6.5

_cache = {}
_cache_lock = threading.Lock()
_last_request_time = [0.0]
_rate_lock = threading.Lock()


def _throttle():
    """NVD'nin istek hizi limitine takilmamak icin istekler arasina bekleme koyar."""
    with _rate_lock:
        elapsed = time.time() - _last_request_time[0]
        if elapsed < MIN_INTERVAL:
            time.sleep(MIN_INTERVAL - elapsed)
        _last_request_time[0] = time.time()


def lookup_cve(cve_id: str) -> dict | None:
    """
    Tek bir CVE ID icin NVD'den resmi kayit ceker.
    Hata olursa (ag, rate limit, bulunamadi) None doner - analiz akisini durdurmaz.
    """
    cve_id = cve_id.upper().strip()

    with _cache_lock:
        if cve_id in _cache:
            return _cache[cve_id]

    try:
        _throttle()
        headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
        resp = requests.get(
            NVD_API_URL,
            params={"cveId": cve_id},
            headers=headers,
            timeout=10,
        )

        if resp.status_code != 200:
            with _cache_lock:
                _cache[cve_id] = None
            return None

        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            with _cache_lock:
                _cache[cve_id] = None
            return None

        cve = vulns[0]["cve"]

        description = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            None,
        )

        cvss_score = None
        cvss_severity = None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss_data = metrics[key][0]["cvssData"]
                cvss_score = cvss_data.get("baseScore")
                cvss_severity = cvss_data.get(
                    "baseSeverity", metrics[key][0].get("baseSeverity")
                )
                break

        result = {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "published": cve.get("published"),
        }

        with _cache_lock:
            _cache[cve_id] = result
        return result

    except Exception:
        # Ag hatasi, timeout, parse hatasi vs. - sessizce atla, analiz devam etsin
        with _cache_lock:
            _cache[cve_id] = None
        return None