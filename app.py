import re
import streamlit as st

from detector import detect_type
from decoders.base64_decoder import decode_base64
from decoders.hex_decoder import decode_hex
from decoders.url_decoder import decode_url
from decoders.rot13_decoder import decode_rot13
from decoders.caesar_decoder import decode_caesar
from decoders.atbash_decoder import decode_atbash
from detectors.cipher_detector import detect_cipher
from detectors.hash_detector import detect_hash
from utils.validators import validate_input

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CipherScope",
    page_icon="🔐",
    layout="centered",
    initial_sidebar_state="expanded",
)

# ── Minimal custom CSS ──────────────────────────────────────────────────────────
st.markdown(
    """
    <style>
    /* Tighten the header stack */
    .cs-title  { font-size: 2.4rem; font-weight: 800; letter-spacing: -0.5px; margin-bottom: 0; }
    .cs-sub    { font-size: 1.05rem; color: #7c868f; margin-top: 0; margin-bottom: 0.25rem; }
    .cs-desc   { font-size: 0.9rem;  color: #9aa3ac; margin-bottom: 1.5rem; }
    .cs-divider{ border: none; border-top: 1px solid #2d3240; margin: 1.25rem 0; }
    /* Section labels */
    .cs-section{ font-size: 0.75rem; font-weight: 700; letter-spacing: 1.5px;
                 text-transform: uppercase; color: #7c868f; margin-bottom: 0.4rem; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ── Sidebar ─────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🔐 CipherScope")
    st.markdown("**Version 1.0**")
    st.divider()
    st.markdown("### Features")
    st.markdown(
        """
- 🔍 Encoding detection
- 🔓 Base64 decoding
- 🔓 Hexadecimal decoding
- 🔓 URL decoding
- 🔓 ROT13 decoding
- 🔓 Caesar cipher analysis
- 🔓 Atbash cipher analysis
- #️⃣ Hash algorithm identification
        """
    )
    st.divider()
    st.info(
        "**Note:** Hash inputs are **identified only** — no cracking or brute-force is performed.",
        icon="ℹ️",
    )
    st.divider()
    st.caption("Built with Streamlit · CipherScope © 2025")

# ── Header ──────────────────────────────────────────────────────────────────────
st.markdown('<p class="cs-title">🔐 CipherScope</p>', unsafe_allow_html=True)
st.markdown('<p class="cs-sub">Cipher &amp; Hash Analyzer</p>', unsafe_allow_html=True)
st.markdown(
    '<p class="cs-desc">Paste any encoded string, hash, or ciphertext — '
    "CipherScope detects and decodes it instantly.</p>",
    unsafe_allow_html=True,
)
st.markdown('<hr class="cs-divider">', unsafe_allow_html=True)

# ── Input ───────────────────────────────────────────────────────────────────────
st.markdown('<p class="cs-section">Input</p>', unsafe_allow_html=True)
input_text = st.text_area(
    label="input_hidden",
    label_visibility="collapsed",
    placeholder="Paste your encoded text, hash, or ciphertext here…",
    height=120,
)

analyze_clicked = st.button("🔍 Analyze", type="primary", use_container_width=True)

# ── Analysis ────────────────────────────────────────────────────────────────────
if analyze_clicked:
    st.markdown('<hr class="cs-divider">', unsafe_allow_html=True)

    # 1. Validate
    valid, error_msg = validate_input(input_text)
    if not valid:
        st.error(f"**Invalid input:** {error_msg}", icon="🚫")
        st.stop()

    stripped = input_text.strip()

    # 2. Detect type
    detection = detect_type(stripped)
    detected_type = detection.type

    st.markdown('<p class="cs-section">Detection Result</p>', unsafe_allow_html=True)

    conf_icon = {"High": "✅", "Medium": "⚠️", "Low": "❓"}.get(detection.confidence, "❓")
    conf_color = {"High": "success", "Medium": "warning", "Low": "info"}.get(
        detection.confidence, "info"
    )

    col_type, col_conf = st.columns(2)
    with col_type:
        st.metric("Detected Type", detected_type)
    with col_conf:
        st.metric("Confidence", f"{conf_icon} {detection.confidence}")

    st.markdown('<hr class="cs-divider">', unsafe_allow_html=True)

    # ── Helper: render a decode result ─────────────────────────────────────────
    def show_decode(result, label: str = "Decoded Output"):
        st.markdown(f'<p class="cs-section">{label}</p>', unsafe_allow_html=True)
        if result.success:
            st.success("Decoding successful", icon="🔓")
            st.code(result.output, language=None)
            st.caption(f"Encoding: **{result.encoding}**")
        else:
            st.error(f"Decoding failed: {result.output}", icon="❌")

    # 3. Known encoding types
    if detected_type == "URL Encoding":
        show_decode(decode_url(stripped))

    elif detected_type == "Base64":
        show_decode(decode_base64(stripped))

    elif detected_type == "Hexadecimal":
        show_decode(decode_hex(stripped))

    elif detected_type == "ROT13":
        show_decode(decode_rot13(stripped))

    # 4. Hash — identify only, no cracking
    elif detected_type.startswith("Hash"):
        hash_candidates = detect_hash(stripped)
        st.markdown('<p class="cs-section">Hash Candidates</p>', unsafe_allow_html=True)
        if hash_candidates:
            st.warning(
                "Hash detected. Candidates shown below — no cracking is performed.",
                icon="#️⃣",
            )
            for c in hash_candidates:
                conf_icon_h = {"High": "✅", "Medium": "⚠️", "Low": "❓"}.get(c.confidence, "❓")
                st.markdown(
                    f"- {conf_icon_h} **{c.algorithm}** &nbsp;`[{c.confidence}]`&nbsp; — {c.note}"
                )
        else:
            st.info("No hash algorithm candidates identified.", icon="ℹ️")

    # 5. Unknown — run classical cipher + hash detection
    elif detected_type == "Unknown":
        cipher_candidates = detect_cipher(stripped)
        hash_candidates = detect_hash(stripped)

        # 6. Best cipher candidate decoded result
        if cipher_candidates:
            top = cipher_candidates[0]

            if top.cipher == "ROT13":
                top_result = decode_rot13(stripped)
            elif top.cipher == "Atbash":
                top_result = decode_atbash(stripped)
            elif top.cipher.startswith("Caesar"):
                m = re.search(r"shift=(\d+)", top.cipher)
                shift = int(m.group(1)) if m else 0
                top_result = decode_caesar(stripped, shift)
            else:
                top_result = None

            if top_result and top_result.success:
                st.markdown(
                    f'<p class="cs-section">Best Cipher Match — {top.cipher} '
                    f"[{top.confidence}]</p>",
                    unsafe_allow_html=True,
                )
                st.success(f"Best match: **{top.cipher}** ({top.confidence} confidence)", icon="🔓")
                st.code(top_result.output, language=None)
                st.caption(f"Encoding: **{top_result.encoding}**")
                st.markdown('<hr class="cs-divider">', unsafe_allow_html=True)

            # All candidates in expanders
            st.markdown(
                '<p class="cs-section">Classical Cipher Candidates</p>',
                unsafe_allow_html=True,
            )
            for c in cipher_candidates:
                conf_icon_c = {"High": "✅", "Medium": "⚠️", "Low": "❓"}.get(c.confidence, "❓")
                preview = c.decoded[:80] + "…" if len(c.decoded) > 80 else c.decoded
                with st.expander(f"{conf_icon_c} {c.cipher}  [{c.confidence}]"):
                    st.code(preview, language=None)
        else:
            st.markdown(
                '<p class="cs-section">Classical Cipher Candidates</p>',
                unsafe_allow_html=True,
            )
            st.info("No classical cipher candidates identified.", icon="ℹ️")

        # Hash candidates (may still exist for unknown hex-looking inputs)
        if hash_candidates:
            st.markdown('<hr class="cs-divider">', unsafe_allow_html=True)
            st.markdown('<p class="cs-section">Hash Candidates</p>', unsafe_allow_html=True)
            st.warning(
                "Hash detected. Candidates shown below — no cracking is performed.",
                icon="#️⃣",
            )
            for c in hash_candidates:
                conf_icon_h = {"High": "✅", "Medium": "⚠️", "Low": "❓"}.get(c.confidence, "❓")
                st.markdown(
                    f"- {conf_icon_h} **{c.algorithm}** &nbsp;`[{c.confidence}]`&nbsp; — {c.note}"
                )
