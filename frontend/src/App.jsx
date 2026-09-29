import { useState } from "react";
import "./App.css";

function App() {
  const [target, setTarget] = useState("");
  const [status, setStatus] = useState(null);

  const startScan = async () => {
    setStatus("Baglaniyor...");
    try {
      const res = await fetch("http://localhost:8000/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target }),
      });
      const data = await res.json();
      setStatus(`Durum: ${data.status} - ${data.note}`);
    } catch (err) {
      setStatus("Backend'e ulasilamadi. 'uvicorn app.main:app --reload' calisiyor mu?");
    }
  };

  return (
    <div className="app-shell">
      <h1>AI Destekli Otonom Pentest Ajani</h1>
      <p className="subtitle">
        Web dashboard - iskelet surum. Hedef girip backend baglantisini test edebilirsin.
      </p>

      <div className="scan-box">
        <input
          type="text"
          placeholder="orn. http://localhost:3000 (Juice Shop)"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
        />
        <button onClick={startScan}>Taramayi Baslat</button>
      </div>

      {status && <p className="status">{status}</p>}

      <footer>
        Sadece izole/yetkili test ortamlarinda kullanin.
      </footer>
    </div>
  );
}

export default App;
