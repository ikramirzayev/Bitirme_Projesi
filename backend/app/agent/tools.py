from app.rag.cve_lookup import lookup_cve
from app.scanners.nuclei_scanner import run_nuclei

TOOLS = [
    {
        "name": "lookup_cve",
        "description": (
            "NVD (National Vulnerability Database) uzerinden bir CVE ID'sinin "
            "resmi aciklamasini ve CVSS skorunu getirir. Tarama sonucunda gecen "
            "veya supheli bir CVE oldugunda, kesin bilgi almak icin kullan."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "Sorgulanacak CVE kimligi, orn. CVE-2021-44228",
                },
                "neden": {
                    "type": "string",
                    "description": "Bu araci su an cagirma gerekcen - kisa, somut bir aciklama",
                },
            },
            "required": ["cve_id", "neden"],
        },
    },
    {
        "name": "run_targeted_nuclei_scan",
        "description": (
            "Belirli bir hedefe, belirli Nuclei etiketleriyle (tags) odaklanmis "
            "ek bir tarama calistirir. Ilk taramadan gelen bilgiyi yetersiz veya "
            "belirsiz buldugunda, supheli bir zafiyet turunu (orn. sqli, xss, "
            "exposed-panels, takeover) daha derinlemesine kontrol etmek icin "
            "kullan. SADECE izole test ortamindaki (127.0.0.1/localhost) "
            "hedeflere karsi kullanilabilir."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Taranacak URL, orn. http://127.0.0.1:8081",
                },
                "tags": {
                    "type": "string",
                    "description": "Virgulle ayrilmis Nuclei etiketleri, orn. 'sqli,xss'",
                },
                "neden": {
                    "type": "string",
                    "description": "Bu araci su an cagirma gerekcen - kisa, somut bir aciklama",
                },
            },
            "required": ["target", "tags", "neden"],
        },
    },
]


def execute_tool(name: str, tool_input: dict) -> dict:
    """Claude'un istedigi araci gercekten calistirir. Hata olursa programi
    coekertmez, Claude'un okuyabilecegi bir hata mesaji doner.

    'neden' alani sadece arayuzde agent'in gerekcesini gostermek icin var -
    gercek fonksiyonlar (lookup_cve, run_nuclei) bu parametreyi bilmiyor,
    o yuzden gercek cagridan once ayikliyoruz."""
    tool_input = dict(tool_input)
    tool_input.pop("neden", None)

    try:
        if name == "lookup_cve":
            result = lookup_cve(tool_input["cve_id"])
            if result is None:
                return {"bulunamadi": True, "cve_id": tool_input["cve_id"]}
            return result

        if name == "run_targeted_nuclei_scan":
            target = tool_input.get("target", "")
            if not (
                target.startswith("http://127.0.0.1")
                or target.startswith("http://localhost")
            ):
                return {
                    "error": (
                        "Guvenlik: sadece izole test ortamina "
                        "(127.0.0.1/localhost) karsi ek tarama yapilabilir."
                    )
                }
            return run_nuclei(target, tags=tool_input.get("tags"))

        return {"error": f"Bilinmeyen arac: {name}"}

    except Exception as e:
        return {"error": str(e)}