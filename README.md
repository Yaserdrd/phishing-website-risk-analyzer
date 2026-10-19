# 🛡️ Phishing Website Risk Analyzer

**An educational phishing URL risk analysis app built with Python, scikit-learn, and Streamlit.**

This project evolved from a Jupyter/Google Colab experiment comparing **Decision Tree**, **Random Forest**, and a **Keras neural network** on the UCI Phishing Websites dataset (ID 327). Its current application uses a **separate URL-text model** based on the UCI PhiUSIIL Phishing URL dataset (ID 967), complemented by URL heuristics and **optional** TLS, RDAP, and HTML checks.

> [!WARNING]
> This is a research prototype, **not a browser protection product**. A low risk score does not establish safety. The combined 0–100 score is heuristic, **not** a calibrated phishing probability. No trained model is shipped, and final URL-model performance has **not been verified** in this distribution.

## Highlights

- **URL text model:** TF-IDF character n-grams (full URL + hostname) and Logistic Regression.
- **Leakage-aware evaluation:** `GroupShuffleSplit` by normalized hostname. Validation selects a high phishing threshold independently of the held-out test set. *Note: grouping by hostname does not fully isolate related subdomains of one registrable domain.*
- **Three-way output:** `PHISHING` / `UNCERTAIN` / `LEGITIMATE` with independently recorded thresholds.
- **Transparent risk breakdown:** URL heuristics plus optional live TLS, RDAP, HTML analysis. Live lookups are OFF by default.
- **SSRF precautions:** active requests accept only HTTP/HTTPS on ports 80/443, reject private/reserved DNS results, connect to a validated pinned public IP, and revalidate every redirect. Bounded response body, redirect count and socket timeouts.
- **Test suite and GitHub Actions** for URL normalization, private IP protections, basic HTML signals, training and application behavior.

## Quick start (local)

Requires **Python 3.10+** and a working internet connection to install packages. Training requires downloading an external public dataset.

```bash
git clone https://github.com/Yaserdrd/phishing-website-risk-analyzer.git
cd phishing-website-risk-analyzer
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install -r requirements.txt
streamlit run app.py
```

Without a `models/url_phishing_model.pkl`, the app starts in **explicit heuristic-only demo mode**. This is intentional: you should not rely on or publish an unverified model. No website is contacted unless the **live checks** checkbox is enabled. The optional active checks contact the submitted website and the public RDAP service.

### Train your own ML model

```bash
python -m pip install -r requirements-train.txt
python scripts/download_uci.py
python scripts/train_model.py --csv data/phiusiil_urls.csv
streamlit run app.py
```

The training script accepts any CSV with these columns:

| Column | Meaning |
| --- | --- |
| `URL` | Full HTTP(S) URL |
| `label` | `0`: phishing; `1`: legitimate |

Malformed URLs are excluded during CSV preparation, with duplicate normalized URLs removed; contradictory labels for the same normalized URL trigger an error.

`train_model.py` writes `models/url_phishing_model.pkl` and `models/url_model_meta.json`, including the validation decision thresholds and held-out test metrics. Both files are **ignored by git**. Only load model artifacts you trained yourself; Python `joblib` serialization can execute code when loading untrusted files.

Re-running on the full dataset can take time. The default feature dimensions and evaluation parameters are documented in `src/phishing_analyzer/model.py`.

### Verify locally

```bash
python -m pip install -r requirements-dev.txt
PYTHONPATH=src pytest -q              # macOS / Linux
$env:PYTHONPATH="src"; pytest -q       # Windows PowerShell
```

## Architecture

```text
User enters URL
      │
      ▼
Normalization & validation  ──► Lexical heuristics
      │
      ├──► Optional local URL-text ML model (TF-IDF + Logistic Regression)
      │
      └──► Optional opt-in network checks
             ├─ Public-IP-pinned TLS handshake
             ├─ RDAP domain-age lookup
             └─ Bounded HTML GET + form/iframe/link analysis
      │
      ▼
Breakdown + combined heuristic risk score + warnings
```

The ML model from the **earlier notebook** is **not** the model serving URL predictions in the application. It required 30 precomputed features and cannot honestly infer them all from just a URL string.

## Dataset and experimental history

| Experiment | Dataset | Source notebook reported accuracy |
| --- | --- | ---: |
| Decision Tree | UCI Phishing Websites, 327 | 95.75% |
| Random Forest (100 trees) | UCI Phishing Websites, 327 | 96.70% |
| Keras neural network | UCI Phishing Websites, 327 | 95.34% |
| Live URL-text model | UCI PhiUSIIL, 967 | **Not verified in supplied notebook** |

The numbers above are **recorded in the source notebook**, not newly reproduced here. They belong to a different dataset/model configuration from the current URL-text app. The full source research notebook is kept separate from the tested application; see `notebooks/README.md`.

Dataset references (CC BY 4.0; datasets not redistributed):

- Mohammad, R. & McCluskey, L. (2012). *Phishing Websites* [Dataset]. UCI Machine Learning Repository. [DOI: 10.24432/C51W2X](https://doi.org/10.24432/C51W2X).
- Prasad, A. & Chandra, S. (2024). *PhiUSIIL Phishing URL (Website)* [Dataset]. UCI Machine Learning Repository. [Dataset page](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset).

## Project structure

```text
app.py                           Streamlit UI (usable without model in demo mode)
src/phishing_analyzer/
  urls.py                        Normalization and input validation
  model.py                       URL model, splits, thresholds, evaluation
  security.py                    Lexical and opt-in network checks
  analyzer.py                    Risk analysis orchestrator
scripts/
  download_uci.py                Download UCI 967 (opt-in)
  train_model.py                 Train/evaluate from CSV
notebooks/                      Clean experimental notebook + notes
tests/                          Automated checks
.github/workflows/tests.yml      Python 3.10–3.12 CI
```

## Limitations and roadmap

1. Training data can age; evaluate on recent phishing attempts before deployment.
2. Hostname grouping leaves potential leakage across sibling subdomains; future training should split by **registrable domain** using the Public Suffix List.
3. Validation/test metrics do not prove the system works on novel real-world websites. Scores and thresholds are not necessarily probability-calibrated.
4. Network/TLS/RDAP failures often indicate missing evidence rather than attacks; use care when interpreting live-check outputs.
5. Form actions, iframes, passwords and external links are weak individual phishing indicators. Treat findings as context, not definitive evidence.
6. Domain fetching is strictly opt-in, but a hardened public deployment should also add request budgets, rate limits, centralized audit controls, deployment-specific egress firewalling, and abuse monitoring.
7. No generative AI API is currently used in the production Streamlit application. Earlier notebook experiments describe such an extension; it is not represented here as a finished feature.

## Responsible use

Analyze links you are authorized to assess. Never submit credentials or secret tokens as URL parameters. See [SECURITY.md](SECURITY.md).

## Türkçe özet

Bu proje oltalama (phishing) bağlantılarını analiz eden **eğitim amaçlı bir prototiptir**. URL metninden özellik çıkararak makine öğrenmesi tahmini üretir; ek olarak isteğe bağlı TLS, RDAP ve HTML kontrolleri sunar. Eğitimli model dosyası bulunmadığında uygulama bunu açıkça bildirerek yalnızca kural tabanlı demo çalıştırır. **Düşük risk puanı güvenlik garantisi değildir.**
