import subprocess
import os
import sys
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
SUBLIST3R_DIR = os.path.join(CURRENT_DIR, "Sublist3r")
def parse_sublist3r_output(raw_output):

    lines = raw_output.split("\n")
    baslangic = None
    for i, line in enumerate(lines):
        if "Total Unique Subdomains Found" in line:
            baslangic = i + 1   # subdomainler baslar
            break

    if baslangic is None:
        return []


    subdomains = [line.strip() for line in lines[baslangic:] if line.strip()]#subdomainlerin basindan sonuna kadar alir 
    return subdomains


def run_subdomain_scan(target):
    result = subprocess.run(
        [sys.executable, "sublist3r.py", "-d", "yahoo.com"],
        cwd=SUBLIST3R_DIR,
        capture_output=True,
        text=True,
    )#komutun ciktisini alir

    if result.returncode != 0:
        return {
            "error": True,
            "message": "Sublist3r calisirken hata verdi.",
            "stderr": result.stderr,
        }#Komut calismazsa 

    subdomains = parse_sublist3r_output(result.stdout)#Parse olunmus

    return {
    "subdomains": subdomains,
    "note": "Bu modul, yerel test ortaminin (localhost) subdomain kavramina sahip "
            "olmamasi nedeniyle, gercek ve zengin bir subdomain yapisina sahip "
            "'yahoo.com' domaini uzerinde PASIF (sadece OSINT) olarak demo amacli calistirilmistir.",
}