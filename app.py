"""Streamlit entry point; boots in transparent passive-demo mode without a model."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))
from phishing_analyzer.analyzer import analyze
from phishing_analyzer.model import load_model


def main():
    import streamlit as st
    st.set_page_config(page_title="Phishing Website Risk Analyzer", page_icon="🛡️", layout="centered")
    st.title("🛡️ Phishing Website Risk Analyzer")
    st.caption("URL text classification, transparent heuristics, and optional active network checks")
    st.info("Research prototype: model decisions and signal scores do **not** prove that a website is safe.")
    @st.cache_resource
    def cached_model():
        return load_model(ROOT / "models")

    model, meta = cached_model()
    if model is None:
        st.warning("ML model not installed. Showing **heuristic-only demo**. Train the URL model first to enable predictions.")
    else:
        st.success("URL ML model loaded")
        st.caption("Model performance is dataset-specific. See models/url_model_meta.json after training.")
    with st.form("scan"):
        user_url = st.text_input("Website URL", placeholder="https://example.org/login")
        active = st.checkbox("Run live SSL/TLS, RDAP and HTML checks (contacts the website)", value=False)
        st.caption("Live checks may contact the submitted website and RDAP service; do not enter private URLs.")
        clicked = st.form_submit_button("Analyze URL", type="primary", use_container_width=True)
    if not clicked:
        return
    try:
        result = analyze(user_url, model, meta, active=active)
    except ValueError as exc:
        st.error(f"Invalid URL: {exc}")
        return
    col1, col2 = st.columns(2)
    ml = result["ml"]
    col1.metric("Model decision", ml["label"] if ml else "UNAVAILABLE")
    col2.metric("Combined signal score", f"{result['risk_score']} / 100")
    st.caption("The signal score combines additive heuristics and any model contribution. "
               "It is not a phishing probability and does not override the model decision.")
    st.progress(result["risk_score"] / 100)
    if ml:
        if ml["label"] == "PHISHING":
            st.error("Model decision: PHISHING. A low signal score does not cancel this warning. "
                     "This model decision may be wrong; it is not a verified threat finding.")
        elif ml["label"] == "UNCERTAIN":
            st.warning("Model decision: UNCERTAIN. The model abstained; a low signal score "
                       "does not establish safety.")
        else:
            st.info("Model decision: LEGITIMATE. This is a model prediction, not verified "
                    "legitimacy or a safety guarantee. Review the other signals separately.")
        st.subheader("Machine learning")
        st.write(f"Model phishing score: {ml['probability']:.6f}")
        st.caption(f"Score thresholds: LEGITIMATE ≤ {ml['low']:.6f}; PHISHING ≥ {ml['high']:.6f}; "
                   "otherwise UNCERTAIN. Scores are not calibrated probabilities.")
    else:
        st.warning("Model decision unavailable. Heuristic-only demo; the signal score "
                   "cannot establish whether this URL is phishing or legitimate.")
    st.subheader("Signals")
    st.write("Scores are additive heuristics, **not calibrated probabilities**.")
    st.json(result["score_parts"])
    if result["findings"]:
        for finding in result["findings"]:
            st.write("• " + finding)
    else:
        st.write("No heuristic warnings were detected; this does not establish safety.")
    if active:
        st.subheader("Live inspection")
        st.json(result["checks"])
    st.caption(result["disclaimer"])


if __name__ == "__main__":
    main()
