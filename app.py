"""Streamlit entry point; boots in transparent passive-demo mode without a model."""
from pathlib import Path
import logging
import os
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))
from phishing_analyzer.analyzer import analyze
from phishing_analyzer.serving import ModelUnavailable, load_app_model, model_revision

LOGGER = logging.getLogger(__name__)


def main():
    import streamlit as st
    st.set_page_config(page_title="Phishing Website Risk Analyzer", page_icon="🛡️", layout="centered")
    st.title("🛡️ Phishing Website Risk Analyzer")
    st.caption("URL text classification, transparent heuristics, and optional active network checks")
    st.info("Research prototype: model decisions and signal scores do **not** prove that a website is safe.")
    @st.cache_resource(show_spinner=False)
    def cached_model(directory, manifest, digest, required, revision):
        """File revision participates in the cache key; content is verified on load."""
        return load_app_model(directory, manifest, digest, required=required)

    directory = os.environ.get("PHISHING_MODEL_DIR") or str(ROOT / "models")
    manifest = os.environ.get("PHISHING_MODEL_MANIFEST") or str(Path(directory) / "frozen_manifest.json")
    digest = os.environ.get("PHISHING_MODEL_MANIFEST_SHA256", "")
    required = bool(digest or os.environ.get("PHISHING_MODEL_MANIFEST") or os.environ.get("PHISHING_MODEL_DIR"))
    blocked = False
    try:
        with st.spinner("Checking model availability…"):
            model, meta = cached_model(directory, manifest, digest, required, model_revision(directory, manifest))
    except ModelUnavailable:
        LOGGER.warning("model_package_unavailable")
        model, meta, blocked = None, None, True
        st.error("The installed model is unavailable or could not be verified. Model predictions are disabled. "
                 "You can still use the URL-only demo checks.")
    if model is None and not blocked:
        st.warning("ML model not installed. Showing **heuristic-only demo**; model predictions are unavailable.")
    elif model is None:
        st.caption("URL-only demo mode is active. No model prediction will be shown.")
    else:
        st.success("Model package verified")
        st.caption("Model results are dataset-specific research estimates and may be wrong.")
    with st.form("scan"):
        user_url = st.text_input("Website URL", placeholder="https://example.org/login")
        active = st.checkbox("Run live SSL/TLS, RDAP and HTML checks (contacts the website)", value=False)
        st.caption("Do not paste passwords, access tokens or private links. Live checks may contact the website "
                   "and RDAP service. URL-only checks do not contact the submitted website.")
        clicked = st.form_submit_button("Analyze URL", type="primary", use_container_width=True)
    if not clicked:
        return
    if not user_url.strip():
        st.warning("Enter a website URL to analyze.")
        return
    try:
        with st.spinner("Analyzing URL…"):
            try:
                result = analyze(user_url, model, meta, active=active)
            except ModelUnavailable:
                LOGGER.warning("model_prediction_unavailable")
                st.error("The model could not provide a prediction. Showing URL-only demo checks for this analysis. "
                         "No model decision is available; you can retry later.")
                result = analyze(user_url, active=active)
    except ValueError as exc:
        st.error(f"Invalid URL: {exc}")
        return
    except Exception:
        LOGGER.error("analysis_unavailable")
        st.error("Analysis could not be completed. Try again. No safety conclusion is available.")
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
