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
    st.info("Research prototype: a LOW risk score does **not** prove that a website is safe.")
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
    col1.metric("Combined risk score", f"{result['risk_score']} / 100")
    col2.metric("Risk level", result["risk_level"])
    st.progress(result["risk_score"] / 100)
    if result["ml"]:
        if result["ml"]["label"] == "UNCERTAIN":
            st.warning("ML result is UNCERTAIN. Do not treat a low heuristic score as proof this URL is safe.")
        st.subheader("Machine learning")
        st.write(f"**{result['ml']['label']}** | Model phishing score: {result['ml']['probability']:.1%}")
        st.caption(f"LEGITIMATE ≤ {result['ml']['low']:.0%}; PHISHING ≥ {result['ml']['high']:.0%}; otherwise UNCERTAIN")
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
