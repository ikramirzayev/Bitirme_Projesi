import warnings
warnings.filterwarnings("ignore")
from Wappalyzer import Wappalyzer, WebPage
import json

def run_tech_detection(target):
    if not target.startswith("http"):
        url = f"http://{target}"
    else:
        url = target

    wappalyzer = Wappalyzer.latest()
    webpage = WebPage.new_from_url(url)
    sonuc = wappalyzer.analyze_with_versions(webpage)
    technologies = []
    for isim, detay in sonuc.items():
        technologies.append({
            "technology": isim,
            "versions": detay.get("versions", []),
        })

    return {"technologies": technologies}
if __name__ == "__main__":
    import json
    sonuc = run_tech_detection("localhost:3000")
    print(json.dumps(sonuc, indent=2, ensure_ascii=False))