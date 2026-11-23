import json
import re

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

MAX_CVE_LOOKUPS = 5  # prompt'u sismesin ve NVD'ye asiri istek gitmesin diye ust sinir


def extract_cve_ids(scan_data: dict) -> list[str]:
    """Tarama sonucunun tamamini (Nmap --script vuln ciktisi, Nuclei template_id/tags dahil)
    metne cevirip icinde gecen CVE ID'lerini bulur."""
    raw_text = json.dumps(scan_data, ensure_ascii=False)
    found = CVE_PATTERN.findall(raw_text)
    unique = []
    for cve in found:
        cve_upper = cve.upper()
        if cve_upper not in unique:
            unique.append(cve_upper)
    return unique[:MAX_CVE_LOOKUPS]


def enrich_with_cve_data(scan_data: dict) -> str:
    """CVE ID'leri bulur, NVD'den resmi kayitlarini ceker, Claude'a eklenecek
    okunabilir bir metin bloguna cevirir. Hicbir CVE bulunamazsa bos string doner."""
    from app.rag.cve_lookup import lookup_cve  # dongusel import onlemek icin burada

    cve_ids = extract_cve_ids(scan_data)
    if not cve_ids:
        return ""

    blocks = []
    for cve_id in cve_ids:
        record = lookup_cve(cve_id)
        if record is None:
            continue
        blocks.append(
            f"- {record['cve_id']} "
            f"(CVSS: {record['cvss_score']} / {record['cvss_severity']}): "
            f"{record['description']}"
        )

    if not blocks:
        return ""

    return (
        "Asagida, tarama sonuclarinda gecen CVE ID'lerine ait NVD "
        "(National Vulnerability Database) resmi kayitlari var. Bu bilgi "
        "guvenilir ve guncel bir kaynaktir - ilgili bulgularin 'neden_onemli' "
        "alaninda bu resmi aciklamalara ve CVSS skoruna atifta bulun:\n\n"
        + "\n".join(blocks)
    )
