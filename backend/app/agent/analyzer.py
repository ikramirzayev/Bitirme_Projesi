import json
import os
from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field
from anthropic import Anthropic

from app.agent.tools import TOOLS, execute_tool

load_dotenv()

client = Anthropic()


class Bulgu(BaseModel):
    model_config = ConfigDict(extra="forbid")

    baslik: str = Field(description="Zafiyetin/bulgunun kisa basligi")
    risk_seviyesi: str = Field(description="dusuk, orta, yuksek veya kritik")
    aciklama: str = Field(description="Bulgunun ne oldugunun teknik aciklamasi")
    neden_onemli: str = Field(description="Bu bulgu NEDEN risk tasiyor - somut, 'cunku...' ile baslayan bir aciklama")
    onerilen_aksiyon: str = Field(description="Bu bulguyu dogrulamak/duzeltmek icin somut, uygulanabilir bir adim")


class AnalizSonucu(BaseModel):
    model_config = ConfigDict(extra="forbid")

    genel_risk_seviyesi: str = Field(description="dusuk, orta, yuksek veya kritik - tum taramanin ozeti")
    ozet: str = Field(description="2-3 cumlelik, teknik olmayan bir yoneticiye anlatir gibi genel ozet")
    bulgular: list[Bulgu] = Field(description="Onem sirasina gore (en kritik once) siralanmis bulgu listesi, en fazla 6 bulgu")


AGENT_SYSTEM_PROMPT = """Sen deneyimli bir sizma testi uzmanisin ve kendi kararlarini
verebilen bir AI ajanisin. Sana ham tarama sonuclari (Nmap, Nuclei, Wappalyzer,
Sublist3r ciktisi) verilecek. Gorevin bu veriyi incelemek, eksik/belirsiz gordugun
yerlerde elindeki araclari (tools) kullanarak EK BILGI toplamak, ve en sonunda
somut, gerekceli bulgular icin yeterli materyali hazirlamaktir.

KARAR SURECIN:
1. RECON: Once elindeki tarama verisini dikkatlice incele.
2. DEGERLENDIRME: Her olasi bulgu icin kendine sor - "bunu dogrulamak veya
   derinlestirmek icin ek bilgiye ihtiyacim var mi?"
   - Veride bir CVE ID goruyorsan ama resmi aciklamasini/CVSS skorunu bilmiyorsan
     -> lookup_cve arabini kullan.
   - Bir port/servis belirsizse ve belirli bir zafiyet turunden (orn. sqli, xss,
     exposed-panels) supheleniyorsan -> run_targeted_nuclei_scan ile ek, odakli
     bir tarama tetikle.
3. ONERI: Yeterli bilgiye sahip oldugunda arac kullanmayi birak; bir sonraki
   mesajda senden nihai rapor istenecek.

KURALLAR:
- Gereksiz yere arac cagirma - sadece gercekten belirsizlik varsa kullan.
- En fazla birkac arac cagrisi yap (zaman/maliyet sinirli).
- Sadece elindeki veriye (ilk tarama + arac sonuclari) dayan, asla uydurma.
"""

FINAL_SYSTEM_PROMPT = """Az once topladigin tum bilgiye (ilk tarama sonucu + arac
cagrilarindan gelen ek veri) dayanarak, bir insan pentester'in raporunda yer
alacak turden somut, eyleme donusturulebilir bulgular uret.

KURALLAR:
- Her bulgu icin 'neden_onemli' alaninda MUTLAKA somut bir gerekce ver.
- Eger arac cagrisiyla resmi bir CVE/CVSS kaydi elde ettiysen, buna acikca atifta
  bulun.
- Sadece elindeki veriye dayan, veride olmayan bir seyi varsayma/uydurma.
- Tarama sonucunda hicbir anlamli bulgu yoksa, bunu durustce belirt.
- Teknik ama anlasilir bir dil kullan.
- En fazla 6 bulgu ver, en onemlilerini sec - kisa ve oz yaz.
"""

MAX_AGENT_ITERATIONS = 4


def _girdi_metni(arac: str, girdi: dict) -> str:
    """Arac girdisini arayuzde tek satirda gosterilecek, insan-okunabilir bir
    cumleye cevirir."""
    if arac == "lookup_cve":
        return f"{girdi.get('cve_id', '?')} icin NVD sorgulandi"
    if arac == "run_targeted_nuclei_scan":
        return (
            f"{girdi.get('target', '?')} hedefine "
            f"'{girdi.get('tags', '?')}' etiketleriyle ek tarama"
        )
    return str(girdi)


def _sonuc_metni(arac: str, sonuc: dict) -> str:
    """Arac sonucunu arayuzde tek satirda gosterilecek, insan-okunabilir bir
    cumleye cevirir."""
    if isinstance(sonuc, dict) and sonuc.get("error"):
        return f"Hata: {sonuc['error']}"
    if arac == "lookup_cve":
        if isinstance(sonuc, dict) and sonuc.get("bulunamadi"):
            return "NVD'de kayit bulunamadi"
        cvss = sonuc.get("cvss_score") if isinstance(sonuc, dict) else None
        return f"CVSS skoru: {cvss}" if cvss is not None else "NVD kaydi getirildi"
    if arac == "run_targeted_nuclei_scan":
        count = sonuc.get("count") if isinstance(sonuc, dict) else None
        return f"{count} bulgu tespit edildi" if count is not None else "Tarama tamamlandi"
    return "Tamamlandi"


def run_agent_loop(scan_data: dict) -> tuple[list, list]:
    """Claude'a arac kullanma hakki tanir; Claude arac istedigi surece calisip
    sonucu geri besler, arac istemeyi biraktiginda konusma gecmisini VE
    arayuzde gosterilecek arac-cagrisi adimlarini (steps) doner."""
    messages = [{
        "role": "user",
        "content": f"Asagidaki tarama sonuclarini incele:\n\n{scan_data}",
    }]

    steps = []

    for i in range(MAX_AGENT_ITERATIONS):
        response = client.messages.create(
            model="claude-haiku-5-5",
            max_tokens=4096,
            system=AGENT_SYSTEM_PROMPT,
            messages=messages,
            tools=TOOLS,
        )

        assistant_content = [
            block for block in response.content if block.type != "thinking"
        ]
        messages.append({"role": "assistant", "content": assistant_content})

        if response.stop_reason != "tool_use":
            break  # Claude artik arac istemiyor, hazir

        tool_results = []
        for block in response.content:
            if block.type == "tool_use":
                print(f"[agent] arac cagrisi (adim {i + 1}): {block.name}({block.input})")
                result = execute_tool(block.name, block.input)
                steps.append({
                    "adim": len(steps) + 1,
                    "arac": block.name,
                    "girdi_metni": _girdi_metni(block.name, block.input),
                    "neden": block.input.get("neden", ""),
                    "sonuc_metni": _sonuc_metni(block.name, result),
                })
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": json.dumps(result, ensure_ascii=False),
                })

        messages.append({"role": "user", "content": tool_results})

    return messages, steps


def analyze_scan_results(scan_data: dict) -> dict:
    schema = AnalizSonucu.model_json_schema()

    conversation, agent_steps = run_agent_loop(scan_data)

    conversation.append({
        "role": "user",
        "content": (
            "Simdi topladigin tum bilgiye dayanarak NIHAI raporu "
            "yapilandirilmis JSON olarak uret."
        ),
    })

    response = client.messages.create(
        model="claude-haiku-5-5",
        max_tokens=8192,
        system=FINAL_SYSTEM_PROMPT,
        messages=conversation,
        output_config={"format": {"type": "json_schema", "schema": schema}},
    )

    print(f"[analyzer] stop_reason = {response.stop_reason}")

    if response.stop_reason == "max_tokens":
        raise RuntimeError("Claude'un cevabi max_tokens limitine takildi, yarida kesildi.")
    if response.stop_reason == "refusal":
        raise RuntimeError("Claude cevabi 'refusal' ile durdurdu - sema ile uyumsuzluk olabilir.")

    text = next(b.text for b in response.content if b.type == "text")
    data = json.loads(text)
    sonuc = AnalizSonucu.model_validate(data).model_dump()
    sonuc["agent_karar_sureci"] = agent_steps
    return sonuc