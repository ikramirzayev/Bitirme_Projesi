import { useState } from "react";
import "./App.css";

const API_BASE = "http://localhost:8000";

const BAGLANTI_HATASI_MESAJI =
  "Backend'e ulasilamadi. Sunucunun (uvicorn) calistigindan emin olup tekrar deneyin.";

function kullaniciyaGosterilecekHata(err) {
  // Tarayici fetch() backend'e hic ulasamadiginda "TypeError: Failed to
  // fetch" gibi teknik bir mesaj firlatir - bunu anlasilir bir Turkce
  // mesaja ceviriyoruz (bkz. NFR-11). Backend'den normal donen hatalar
  // (orn. "hedef gecersiz") zaten anlasilir oldugu icin oldugu gibi kalir.
  if (err instanceof TypeError) {
    return BAGLANTI_HATASI_MESAJI;
  }
  return err.message || BAGLANTI_HATASI_MESAJI;
}

const MODULE_LABELS = {
  nmap: "Nmap Port Taramasi",
  subdomains: "Subdomain Taramasi (Sublist3r)",
  tech_juice: "Teknoloji Tespiti - Juice Shop",
  tech_dvwa: "Teknoloji Tespiti - DVWA",
  nuclei_juice: "Zafiyet Taramasi - Juice Shop (Nuclei)",
  nuclei_dvwa: "Zafiyet Taramasi - DVWA (Nuclei)",
};

function riskRengi(seviye) {
  const s = (seviye || "").toLowerCase();
  if (s === "kritik") return "risk-kritik";
  if (s === "yuksek") return "risk-yuksek";
  if (s === "orta") return "risk-orta";
  if (s === "dusuk") return "risk-dusuk";
  return "risk-bilinmiyor";
}

function severityRengi(sev) {
  const s = (sev || "").toLowerCase();
  if (s === "critical") return "risk-kritik";
  if (s === "high") return "risk-yuksek";
  if (s === "medium") return "risk-orta";
  if (s === "low") return "risk-dusuk";
  return "risk-bilinmiyor";
}

function cardAccent(seviye) {
  const s = (seviye || "").toLowerCase();
  if (s === "kritik" || s === "critical") return "card-kritik";
  if (s === "yuksek" || s === "high") return "card-yuksek";
  if (s === "orta" || s === "medium") return "card-orta";
  if (s === "dusuk" || s === "low") return "card-dusuk";
  return "card-bilinmiyor";
}

function NucleiFindings({ title, data }) {
  if (!data) return null;
  if (data.error) {
    return (
      <div className="sub-section">
        <h3>{title}</h3>
        <p className="status error">{data.message}</p>
      </div>
    );
  }
  return (
    <div className="sub-section">
      <h3>{title}</h3>
      {data.count === 0 ? (
        <p className="muted">Bulgu yok.</p>
      ) : (
        <div className="finding-list">
          {data.findings.map((f, i) => (
            <div key={i} className={`finding-card ${cardAccent(f.severity)}`}>
              <div className="finding-header">
                <span className="finding-title">{f.name || f.template_id}</span>
                <span className={`risk-pill ${severityRengi(f.severity)}`}>
                  {f.severity}
                </span>
              </div>
              <p className="finding-text">{f.matched_at}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function AgentKararSureci({ steps }) {
  if (!steps || steps.length === 0) {
    return (
      <p className="muted">
        Agent, ilk tarama verisini yeterli buldu ve ek bir arac cagirmadan
        nihai raporu uretti.
      </p>
    );
  }
  return (
    <div className="agent-steps">
      {steps.map((s, i) => (
        <div key={i} className="agent-step-card">
          <div className="agent-step-header">
            <span className="agent-step-badge">Adim {s.adim}</span>
            <span className="agent-step-tool">{s.girdi_metni}</span>
          </div>
          {s.neden && (
            <p className="agent-step-neden">
              <b>Gerekce:</b> {s.neden}
            </p>
          )}
          <p className="agent-step-result">{s.sonuc_metni}</p>
        </div>
      ))}
    </div>
  );
}

function TechList({ data }) {
  if (data?.error) {
    return <p className="status error">{data.message}</p>;
  }
  const items = data?.technologies || [];
  if (items.length === 0) {
    return <p className="muted">Teknoloji tespit edilemedi.</p>;
  }
  return (
    <ul className="tech-list">
      {items.map((t, i) => (
        <li key={i}>
          {t.technology}
          {t.versions && t.versions.length > 0 ? ` (${t.versions.join(", ")})` : ""}
        </li>
      ))}
    </ul>
  );
}

function getPortsArray(nmapResult) {
  if (!nmapResult) return [];
  if (Array.isArray(nmapResult.ports)) return nmapResult.ports;
  if (Array.isArray(nmapResult.hosts)) {
    return nmapResult.hosts.flatMap((h) => h.ports || []);
  }
  return [];
}

function getField(obj, keys) {
  for (const k of keys) {
    if (obj[k] !== undefined && obj[k] !== null) return obj[k];
  }
  return "-";
}

function VulnOutput({ result, subdomainsExpanded, onToggleSubdomains }) {
  if (!result) return null;

  const allSubdomains = result.subdomains?.subdomains || [];
  const visibleSubdomains = subdomainsExpanded
    ? allSubdomains
    : allSubdomains.slice(0, 3);

  const nmapPorts = getPortsArray(result.nmap);

  return (
    <>
      <div className="results result-section">
        <h2>Nmap Port Taramasi</h2>
        {result.nmap?.error ? (
          <p className="status error">{result.nmap.message}</p>
        ) : (
          <>
            <table className="host-card">
              <thead>
                <tr>
                  <th>Port</th>
                  <th>Durum</th>
                  <th>Servis</th>
                  <th>Detay</th>
                </tr>
              </thead>
              <tbody>
                {nmapPorts.map((p, i) => (
                  <tr key={i}>
                    <td>{getField(p, ["port", "Port"])}</td>
                    <td>{getField(p, ["state", "durum", "Durum"])}</td>
                    <td>{getField(p, ["service", "servis", "Servis"])}</td>
                    <td>
                      {p.product || p.version
                        ? `${p.product || ""} ${p.version || ""}`.trim()
                        : "-"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {nmapPorts.length === 0 && (
              <>
                <p className="muted">Port verisi bulunamadi veya alan adlari eslemiyor.</p>
                <pre className="debug-dump">
                  {JSON.stringify(result.nmap, null, 2)}
                </pre>
              </>
            )}
          </>
        )}
      </div>

      <div className="results result-section">
        <h2>Subdomain Taramasi</h2>
        {result.subdomains?.error ? (
          <p className="status error">{result.subdomains.message}</p>
        ) : (
          <>
            <ul className="subdomain-list">
              {visibleSubdomains.map((s, i) => (
                <li key={i}>{s}</li>
              ))}
            </ul>
            {allSubdomains.length > 3 && (
              <button className="detail-btn" onClick={onToggleSubdomains}>
                {subdomainsExpanded
                  ? "Daha Az Goster"
                  : `Detayli Incele (${allSubdomains.length} subdomain)`}
              </button>
            )}
            {result.subdomains?.note && (
              <p className="note">{result.subdomains.note}</p>
            )}
          </>
        )}
      </div>

      <div className="results result-section">
        <h2>Teknoloji Tespiti</h2>
        <div className="sub-section">
          <h3>Juice Shop</h3>
          <TechList data={result.technologies?.juice_shop} />
        </div>
        <div className="sub-section">
          <h3>DVWA</h3>
          <TechList data={result.technologies?.dvwa} />
        </div>
      </div>

      <div className="results result-section">
        <h2>Zafiyet Taramasi (Nuclei)</h2>
        <NucleiFindings title="Juice Shop" data={result.nuclei?.nuclei_juice} />
        <NucleiFindings title="DVWA" data={result.nuclei?.nuclei_dvwa} />
      </div>
    </>
  );
}

function App() {
  const [target, setTarget] = useState("127.0.0.1");
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState({});
  const [percent, setPercent] = useState(0);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [lastJobId, setLastJobId] = useState(null);
  const [subdomainsExpanded, setSubdomainsExpanded] = useState(false);

  const [analysis, setAnalysis] = useState(null);
  const [analysisLoading, setAnalysisLoading] = useState(false);
  const [analysisError, setAnalysisError] = useState(null);

  const totalModules = Object.keys(MODULE_LABELS).length;

  const startScan = async () => {
    setLoading(true);
    setError(null);
    setResult(null);
    setAnalysis(null);
    setAnalysisError(null);
    setProgress({});
    setPercent(0);
    setSubdomainsExpanded(false);
    setLastJobId(null);

    try {
      const startRes = await fetch(`${API_BASE}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target }),
      });

      if (!startRes.ok) {
        const errBody = await startRes.json();
        throw new Error(errBody.detail || "Tarama baslatilamadi.");
      }

      const { job_id } = await startRes.json();

      const intervalId = setInterval(async () => {
        try {
          const statusRes = await fetch(`${API_BASE}/scan/status/${job_id}`);
          if (!statusRes.ok) {
            clearInterval(intervalId);
            setLoading(false);
            setError("Tarama durumu alinamadi.");
            return;
          }

          const statusData = await statusRes.json();
          setProgress(statusData.progress || {});

          const doneCount = Object.values(statusData.progress || {}).filter(
            (s) => s === "done"
          ).length;
          setPercent(Math.round((doneCount / totalModules) * 100));

          if (statusData.status === "finished") {
            clearInterval(intervalId);
            setResult(statusData.result);
            setLoading(false);
            setLastJobId(job_id);
          } else if (statusData.status === "error") {
            clearInterval(intervalId);
            setLoading(false);
            setError(statusData.error || "Tarama sirasinda hata olustu.");
          }
        } catch (pollErr) {
          clearInterval(intervalId);
          setLoading(false);
          setError(kullaniciyaGosterilecekHata(pollErr));
        }
      }, 1200);
    } catch (err) {
      setLoading(false);
      setError(kullaniciyaGosterilecekHata(err));
    }
  };

  const runAnalysis = async () => {
    if (!lastJobId) return;
    setAnalysisLoading(true);
    setAnalysisError(null);
    setAnalysis(null);
    try {
      const analyzeRes = await fetch(`${API_BASE}/analyze/${lastJobId}`, {
        method: "POST",
      });
      if (!analyzeRes.ok) {
        const errBody = await analyzeRes.json();
        throw new Error(errBody.detail || "Analiz basarisiz.");
      }
      const analyzeData = await analyzeRes.json();
      setAnalysis(analyzeData);
    } catch (analyzeErr) {
      setAnalysisError(kullaniciyaGosterilecekHata(analyzeErr));
    } finally {
      setAnalysisLoading(false);
    }
  };

  return (
    <div className="app-shell">
      <header className="app-header">
        <h1>AI Destekli Otonom Pentest Ajani</h1>
        <p className="subtitle">
          Nmap, Sublist3r, Wappalyzer ve Nuclei ile otomatik recon + Claude ile
          akilli bulgular
        </p>
      </header>

      <div className="scan-controls">
        <input
          type="text"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="Hedef (orn. 127.0.0.1)"
          disabled={loading}
        />
        <button onClick={startScan} disabled={loading}>
          {loading ? "Taraniyor..." : "Taramayi Baslat"}
        </button>
      </div>

      {loading && (
        <div className="scan-progress">
          <div className="radar-wrapper">
            <div className="radar-ring radar-ring-outer" />
            <div className="radar-ring radar-ring-mid" />
            <div className="radar-ring radar-ring-inner" />
            <div className="radar-sweep" />
            <div className="radar-dot" />
          </div>

          <div className="progress-bar-track">
            <div
              className="progress-bar-fill"
              style={{ width: `${percent}%` }}
            />
          </div>
          <p className="progress-percent">%{percent}</p>

          <ul className="module-progress-list">
            {Object.entries(MODULE_LABELS).map(([key, label]) => (
              <li key={key} className={progress[key] === "done" ? "done" : ""}>
                {progress[key] === "done" ? "[Tamamlandi]" : "[Bekliyor]"} {label}
              </li>
            ))}
          </ul>
        </div>
      )}

      {error && <p className="status error">{error}</p>}

      <VulnOutput
        result={result}
        subdomainsExpanded={subdomainsExpanded}
        onToggleSubdomains={() => setSubdomainsExpanded((v) => !v)}
      />

      {result && !loading && (
        <div className="analyze-trigger">
          <button onClick={runAnalysis} disabled={analysisLoading}>
            {analysisLoading ? "Analiz Ediliyor..." : "AI Analizi Yap"}
          </button>
        </div>
      )}

      {analysisError && (
        <p className="status error">AI Analizi: {analysisError}</p>
      )}

      {analysis && (
        <div className="results result-section ai-analysis">
          <h2>AI Analizi</h2>
          <div className={`risk-badge ${riskRengi(analysis.genel_risk_seviyesi)}`}>
            Genel Risk: {analysis.genel_risk_seviyesi?.toUpperCase()}
          </div>
          <p className="ai-summary">{analysis.ozet}</p>

          <div className="sub-section agent-steps-section">
            <h3>Agent Karar Sureci</h3>
            <AgentKararSureci steps={analysis.agent_karar_sureci} />
          </div>

          {analysis.bulgular && analysis.bulgular.length > 0 ? (
            analysis.bulgular.map((b, i) => (
              <div key={i} className={`finding-card ${cardAccent(b.risk_seviyesi)}`}>
                <div className="finding-header">
                  <span className="finding-title">{b.baslik}</span>
                  <span className={`risk-pill ${riskRengi(b.risk_seviyesi)}`}>
                    {b.risk_seviyesi}
                  </span>
                </div>
                <p className="finding-text">{b.aciklama}</p>
                <p className="finding-why">
                  <b>Neden onemli:</b> {b.neden_onemli}
                </p>
                <p className="finding-action">
                  <b>Onerilen aksiyon:</b> {b.onerilen_aksiyon}
                </p>
              </div>
            ))
          ) : (
            <p className="muted">Belirgin bir bulgu raporlanmadi.</p>
          )}
        </div>
      )}

      <footer className="app-footer">
        <p>Bitirme Projesi - Ikram Irzayev - Bilgisayar Muhendisligi</p>
      </footer>
    </div>
  );
}

export default App;