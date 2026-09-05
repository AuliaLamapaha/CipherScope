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

# ── Session state ──────────────────────────────────────────────────────────────
if "dark_mode" not in st.session_state:
    st.session_state.dark_mode = False

dark = st.session_state.dark_mode

# ── Theme tokens ───────────────────────────────────────────────────────────────
if dark:
    BG        = "#11131f"
    SURFACE   = "#181b2e"
    SURFACE2  = "#1e2236"
    BORDER    = "#2a2f4a"
    TEXT      = "#e4e6f0"
    MUTED     = "#737a9e"
    ACCENT    = "#a78bfa"
    CYAN      = "#67e8f9"
    SUCCESS   = "#6ee7b7"
    WARN      = "#fde68a"
    ERR       = "#fca5a5"
    CODE_BG   = "#0f1120"
else:
    BG        = "#f4f5fb"
    SURFACE   = "#ffffff"
    SURFACE2  = "#eceef8"
    BORDER    = "#dde0f0"
    TEXT      = "#1a1c2e"
    MUTED     = "#6b7280"
    ACCENT    = "#7c3aed"
    CYAN      = "#0891b2"
    SUCCESS   = "#059669"
    WARN      = "#92400e"
    ERR       = "#b91c1c"
    CODE_BG   = "#eef0f8"

# ── Global CSS ─────────────────────────────────────────────────────────────────
st.markdown(f"""
<style>
/* Base */
html, body, [data-testid="stAppViewContainer"] {{
    background-color: {BG} !important;
    color: {TEXT} !important;
    font-family: -apple-system, "Segoe UI", system-ui, sans-serif;
}}
[data-testid="stMain"] > div {{
    background-color: {BG} !important;
}}
section[data-testid="stSidebar"] {{
    background-color: {SURFACE} !important;
    border-right: 1px solid {BORDER} !important;
}}
section[data-testid="stSidebar"] * {{
    color: {TEXT} !important;
}}
/* Hide default Streamlit header chrome */
header[data-testid="stHeader"] {{
    background: transparent !important;
}}
/* Scrollbar */
::-webkit-scrollbar {{ width: 6px; }}
::-webkit-scrollbar-track {{ background: {SURFACE2}; }}
::-webkit-scrollbar-thumb {{ background: {BORDER}; border-radius: 3px; }}

/* ── Typography helpers ── */
.cs-logo {{
    font-size: 1.9rem;
    font-weight: 800;
    letter-spacing: -0.5px;
    color: {ACCENT};
    margin: 0;
    line-height: 1.15;
}}
.cs-tagline {{
    font-size: 0.95rem;
    font-weight: 600;
    color: {TEXT};
    margin: 0.1rem 0 0.1rem 0;
}}
.cs-desc {{
    font-size: 0.82rem;
    color: {MUTED};
    margin: 0 0 1.2rem 0;
}}
.cs-label {{
    font-size: 0.67rem;
    font-weight: 700;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: {MUTED};
    margin: 0 0 0.45rem 0;
}}
.cs-divider {{
    border: none;
    border-top: 1px solid {BORDER};
    margin: 1.1rem 0;
}}

/* ── Toggle ── */
.cs-toggle-wrap {{
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 4px;
    padding-top: 0.35rem;
}}
.cs-toggle-label {{
    font-size: 0.65rem;
    font-weight: 600;
    letter-spacing: 0.5px;
    text-transform: uppercase;
    color: {MUTED};
}}

/* ── Cards ── */
.cs-card {{
    background: {SURFACE};
    border: 1px solid {BORDER};
    border-radius: 14px;
    padding: 1.1rem 1.3rem;
    margin-bottom: 0.9rem;
}}
.cs-card-success {{
    background: {SURFACE};
    border: 1px solid {SUCCESS}66;
    border-left: 4px solid {SUCCESS};
    border-radius: 14px;
    padding: 1.1rem 1.3rem;
    margin-bottom: 0.9rem;
}}
.cs-card-warn {{
    background: {SURFACE};
    border: 1px solid {WARN}66;
    border-left: 4px solid {WARN};
    border-radius: 14px;
    padding: 1.1rem 1.3rem;
    margin-bottom: 0.9rem;
}}
.cs-card-error {{
    background: {SURFACE};
    border: 1px solid {ERR}66;
    border-left: 4px solid {ERR};
    border-radius: 14px;
    padding: 1.1rem 1.3rem;
    margin-bottom: 0.9rem;
}}

/* ── Metrics ── */
.cs-metric-grid {{
    display: flex;
    gap: 1rem;
    flex-wrap: wrap;
}}
.cs-metric {{
    flex: 1;
    min-width: 110px;
    background: {SURFACE2};
    border: 1px solid {BORDER};
    border-radius: 10px;
    padding: 0.75rem 1rem;
    text-align: center;
}}
.cs-metric-label {{
    font-size: 0.63rem;
    font-weight: 700;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    color: {MUTED};
    margin-bottom: 0.3rem;
}}
.cs-metric-val {{
    font-size: 1.05rem;
    font-weight: 700;
    color: {TEXT};
}}

/* ── Code output ── */
.cs-code {{
    background: {CODE_BG};
    border: 1px solid {BORDER};
    border-radius: 8px;
    padding: 0.75rem 0.95rem;
    font-family: "JetBrains Mono","Fira Mono","Consolas",monospace;
    font-size: 0.9rem;
    color: {TEXT};
    white-space: pre-wrap;
    word-break: break-all;
    margin: 0.5rem 0 0.4rem 0;
    line-height: 1.55;
}}

/* ── Badges ── */
.badge {{
    display: inline-block;
    font-size: 0.67rem;
    font-weight: 700;
    letter-spacing: 0.4px;
    padding: 2px 9px;
    border-radius: 99px;
    text-transform: uppercase;
}}
.b-high   {{ background:{SUCCESS}20; color:{SUCCESS}; border:1px solid {SUCCESS}50; }}
.b-medium {{ background:{WARN}20;    color:{WARN};    border:1px solid {WARN}50; }}
.b-low    {{ background:{MUTED}20;   color:{MUTED};   border:1px solid {MUTED}50; }}

/* ── Hash / cipher rows ── */
.h-row {{
    display: flex;
    align-items: center;
    gap: 0.55rem;
    padding: 0.45rem 0;
    border-bottom: 1px solid {BORDER};
    font-size: 0.88rem;
}}
.h-row:last-child {{ border-bottom: none; }}
.h-algo {{ font-weight: 700; color: {ACCENT}; }}
.h-note {{ color: {MUTED}; font-size: 0.8rem; }}

.c-row {{
    padding: 0.5rem 0;
    border-bottom: 1px solid {BORDER};
}}
.c-row:last-child {{ border-bottom: none; }}
.c-name {{ font-weight: 700; color: {CYAN}; font-size: 0.88rem; }}
.c-preview {{
    background: {CODE_BG};
    border-radius: 6px;
    padding: 0.3rem 0.6rem;
    font-family: "JetBrains Mono","Consolas",monospace;
    font-size: 0.8rem;
    color: {TEXT};
    margin-top: 0.3rem;
    word-break: break-all;
    line-height: 1.5;
}}

/* ── Counter ── */
.cs-counter {{
    font-size: 0.72rem;
    color: {MUTED};
    text-align: right;
    margin: -0.3rem 0 0.5rem 0;
}}

/* ── Analyze button ── */
div[data-testid="stButton"] > button[kind="primary"] {{
    background: linear-gradient(135deg, {ACCENT} 0%, #6d28d9 100%) !important;
    color: #fff !important;
    border: none !important;
    border-radius: 10px !important;
    font-weight: 700 !important;
    font-size: 0.97rem !important;
    padding: 0.52rem 0 !important;
    letter-spacing: 0.3px !important;
    transition: opacity 0.15s ease !important;
    box-shadow: 0 2px 10px {ACCENT}40 !important;
}}
div[data-testid="stButton"] > button[kind="primary"]:hover {{
    opacity: 0.85 !important;
}}
/* Small secondary buttons (toggle) */
div[data-testid="stButton"] > button[kind="secondary"] {{
    background: {SURFACE2} !important;
    color: {TEXT} !important;
    border: 1px solid {BORDER} !important;
    border-radius: 8px !important;
    font-size: 0.78rem !important;
    font-weight: 600 !important;
    padding: 0.3rem 0 !important;
    transition: background 0.12s ease !important;
}}
div[data-testid="stButton"] > button[kind="secondary"]:hover {{
    background: {BORDER} !important;
}}

/* ── Tip bar ── */
.cs-tip {{
    background: {SURFACE2};
    border: 1px solid {BORDER};
    border-radius: 9px;
    padding: 0.55rem 0.95rem;
    font-size: 0.78rem;
    color: {MUTED};
    margin-top: 1rem;
    line-height: 1.7;
}}
.cs-tip code {{
    background: {CODE_BG};
    border-radius: 4px;
    padding: 1px 5px;
    font-size: 0.78rem;
    color: {ACCENT};
    font-family: "JetBrains Mono","Consolas",monospace;
}}
</style>
""", unsafe_allow_html=True)

# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown(
        f'<p style="font-size:1.2rem;font-weight:800;color:{ACCENT};margin:0 0 2px 0">🔐 CipherScope</p>'
        f'<p style="font-size:0.72rem;color:{MUTED};margin:0 0 0.8rem 0;letter-spacing:0.5px">v1.0</p>',
        unsafe_allow_html=True,
    )
    st.divider()
    st.markdown(
        f'<p style="font-size:0.65rem;font-weight:700;letter-spacing:2px;'
        f'text-transform:uppercase;color:{MUTED};margin-bottom:0.5rem">Features</p>',
        unsafe_allow_html=True,
    )
    for icon, label in [
        ("🔍", "Encoding detection"),
        ("🔓", "Base64 · Hex · URL · ROT13"),
        ("🔐", "Caesar · Atbash cipher"),
        ("#️⃣", "Hash identification"),
        ("✅", "Input validation"),
    ]:
        st.markdown(
            f'<p style="margin:5px 0;font-size:0.85rem;color:{TEXT}">{icon}&nbsp; {label}</p>',
            unsafe_allow_html=True,
        )
    st.divider()
    st.markdown(
        f'<div style="background:{SURFACE2};border:1px solid {BORDER};border-radius:9px;'
        f'padding:0.55rem 0.8rem;font-size:0.78rem;color:{MUTED};line-height:1.6">'
        f'#️⃣ &nbsp;Hashes are <b style="color:{TEXT}">identified only</b>.'
        f'<br>No cracking or brute-force.</div>',
        unsafe_allow_html=True,
    )
    st.divider()
    st.markdown(
        f'<p style="font-size:0.72rem;color:{MUTED}">CipherScope &middot; v1.0</p>',
        unsafe_allow_html=True,
    )

# ── Header + toggle row ────────────────────────────────────────────────────────
col_brand, col_toggle = st.columns([5, 1])

with col_brand:
    st.markdown(
        f'<p class="cs-logo">🔐 CipherScope</p>'
        f'<p class="cs-tagline">Decode it. Understand it.</p>'
        f'<p class="cs-desc">Your little toolkit for ciphers &amp; hashes.</p>',
        unsafe_allow_html=True,
    )

with col_toggle:
    # ── Day/Night scene pill ───────────────────────────────────────────────────
    if dark:
        scene = f"""
        <div class="cs-toggle-wrap">
          <div style="
            width:64px;height:30px;border-radius:15px;
            background:#0f1530;border:1.5px solid #2a3460;
            position:relative;overflow:hidden;
            display:flex;align-items:center;justify-content:flex-end;padding-right:5px;">
            <div style="position:absolute;left:7px; top:5px; width:3px;height:3px;border-radius:50%;background:#c8d0f0;opacity:0.9"></div>
            <div style="position:absolute;left:15px;top:13px;width:2px;height:2px;border-radius:50%;background:#c8d0f0;opacity:0.7"></div>
            <div style="position:absolute;left:22px;top:6px; width:2px;height:2px;border-radius:50%;background:#c8d0f0;opacity:0.8"></div>
            <div style="
              width:16px;height:16px;border-radius:50%;
              background:#d8e0f8;
              box-shadow:-4px 1px 0 0 #0f1530;
              position:relative;z-index:1;flex-shrink:0"></div>
          </div>
          <span class="cs-toggle-label">Dark</span>
        </div>"""
    else:
        scene = f"""
        <div class="cs-toggle-wrap">
          <div style="
            width:64px;height:30px;border-radius:15px;
            background:#bae6fd;border:1.5px solid #7dd3fc;
            position:relative;overflow:hidden;
            display:flex;align-items:center;justify-content:flex-start;padding-left:5px;">
            <div style="position:absolute;right:5px; top:7px; width:16px;height:7px;border-radius:4px;background:rgba(255,255,255,0.9)"></div>
            <div style="position:absolute;right:13px;top:4px; width:11px;height:9px;border-radius:6px;background:rgba(255,255,255,0.9)"></div>
            <div style="
              width:16px;height:16px;border-radius:50%;
              background:#fbbf24;
              box-shadow:0 0 5px 2px #fde68a88;
              position:relative;z-index:1;flex-shrink:0"></div>
          </div>
          <span class="cs-toggle-label">Light</span>
        </div>"""

    st.markdown(scene, unsafe_allow_html=True)
    btn_label = "→ Dark" if not dark else "→ Light"
    if st.button(btn_label, key="theme_btn", use_container_width=True):
        st.session_state.dark_mode = not st.session_state.dark_mode
        st.rerun()

st.markdown('<hr class="cs-divider">', unsafe_allow_html=True)

# ── Input ──────────────────────────────────────────────────────────────────────
st.markdown('<p class="cs-label">Input</p>', unsafe_allow_html=True)
input_text = st.text_area(
    label="cs_input",
    label_visibility="collapsed",
    placeholder="Paste encoded text, a hash, or ciphertext here…",
    height=130,
)
char_count = len(input_text)
st.markdown(
    f'<p class="cs-counter">{char_count:,} / 10,000 characters</p>',
    unsafe_allow_html=True,
)

analyze_clicked = st.button("Analyze", type="primary", use_container_width=True)

# ── Analysis ───────────────────────────────────────────────────────────────────
if analyze_clicked:
    st.markdown('<hr class="cs-divider">', unsafe_allow_html=True)

    # 1. Validate
    valid, error_msg = validate_input(input_text)
    if not valid:
        st.markdown(
            f'<div class="cs-card-error">🚫 &nbsp;<b>Invalid input:</b> {error_msg}</div>',
            unsafe_allow_html=True,
        )
        st.stop()

    stripped = input_text.strip()

    # 2. Detect type
    detection = detect_type(stripped)
    detected_type = detection.type

    # ── Detection card ─────────────────────────────────────────────────────────
    st.markdown('<p class="cs-label">Detection</p>', unsafe_allow_html=True)

    conf_icon = {"High": "✅", "Medium": "⚠️", "Low": "❓"}.get(detection.confidence, "❓")

    st.markdown(f"""
    <div class="cs-card">
      <div class="cs-metric-grid">
        <div class="cs-metric">
          <div class="cs-metric-label">Detected Type</div>
          <div class="cs-metric-val" style="color:{ACCENT}">{detected_type}</div>
        </div>
        <div class="cs-metric">
          <div class="cs-metric-label">Confidence</div>
          <div class="cs-metric-val">{conf_icon}&nbsp;{detection.confidence}</div>
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<hr class="cs-divider">', unsafe_allow_html=True)

    # ── Helper: decode result card ─────────────────────────────────────────────
    def show_decode(result):
        st.markdown('<p class="cs-label">Decoded Output</p>', unsafe_allow_html=True)
        if result.success:
            st.markdown(f"""
            <div class="cs-card-success">
              <div style="font-size:0.8rem;font-weight:700;color:{SUCCESS};margin-bottom:0.45rem">
                🔓&nbsp; Decoding successful
              </div>
              <div class="cs-code">{result.output}</div>
              <div style="font-size:0.73rem;color:{MUTED};margin-top:0.35rem">
                Encoding: <b style="color:{TEXT}">{result.encoding}</b>
              </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(
                f'<div class="cs-card-error">❌&nbsp; <b>Decoding failed:</b> {result.output}</div>',
                unsafe_allow_html=True,
            )

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
        st.markdown('<p class="cs-label">Hash Candidates</p>', unsafe_allow_html=True)
        if hash_candidates:
            rows = "".join(
                f'<div class="h-row">'
                f'<span class="badge {"b-high" if c.confidence=="High" else "b-medium" if c.confidence=="Medium" else "b-low"}">'
                f'{c.confidence}</span>'
                f'<span class="h-algo">{c.algorithm}</span>'
                f'<span class="h-note">— {c.note}</span>'
                f'</div>'
                for c in hash_candidates
            )
            st.markdown(f"""
            <div class="cs-card-warn">
              <div style="font-size:0.8rem;font-weight:700;color:{WARN};margin-bottom:0.7rem">
                #️⃣&nbsp; Hash detected — identification only, no cracking performed
              </div>
              {rows}
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(
                f'<div class="cs-card" style="color:{MUTED};font-size:0.88rem">ℹ️&nbsp; No hash algorithm candidates identified.</div>',
                unsafe_allow_html=True,
            )

    # 5. Unknown — run classical cipher + hash detection
    elif detected_type == "Unknown":
        cipher_candidates = detect_cipher(stripped)
        hash_candidates = detect_hash(stripped)

        # 6. Best cipher candidate
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
                top_badge = {"High": "b-high", "Medium": "b-medium", "Low": "b-low"}.get(top.confidence, "b-low")
                st.markdown('<p class="cs-label">Best Cipher Match</p>', unsafe_allow_html=True)
                st.markdown(f"""
                <div class="cs-card-success">
                  <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.5rem;flex-wrap:wrap">
                    <span style="font-size:0.82rem;font-weight:700;color:{SUCCESS}">🔓 Best match:</span>
                    <span style="font-weight:700;color:{CYAN}">{top.cipher}</span>
                    <span class="badge {top_badge}">{top.confidence}</span>
                  </div>
                  <div class="cs-code">{top_result.output}</div>
                  <div style="font-size:0.73rem;color:{MUTED};margin-top:0.35rem">
                    Encoding: <b style="color:{TEXT}">{top_result.encoding}</b>
                  </div>
                </div>
                """, unsafe_allow_html=True)
                st.markdown('<hr class="cs-divider">', unsafe_allow_html=True)

            # All candidates
            st.markdown('<p class="cs-label">Classical Cipher Candidates</p>', unsafe_allow_html=True)
            rows_c = "".join(
                f'<div class="c-row">'
                f'<div style="display:flex;align-items:center;gap:0.45rem">'
                f'<span class="c-name">{c.cipher}</span>'
                f'<span class="badge {"b-high" if c.confidence=="High" else "b-medium" if c.confidence=="Medium" else "b-low"}">'
                f'{c.confidence}</span></div>'
                f'<div class="c-preview">{c.decoded[:80] + "…" if len(c.decoded) > 80 else c.decoded}</div>'
                f'</div>'
                for c in cipher_candidates
            )
            st.markdown(f'<div class="cs-card">{rows_c}</div>', unsafe_allow_html=True)
        else:
            st.markdown('<p class="cs-label">Classical Cipher Candidates</p>', unsafe_allow_html=True)
            st.markdown(
                f'<div class="cs-card" style="color:{MUTED};font-size:0.88rem">ℹ️&nbsp; No classical cipher candidates identified.</div>',
                unsafe_allow_html=True,
            )

        # Hash candidates (unknown path)
        if hash_candidates:
            st.markdown('<hr class="cs-divider">', unsafe_allow_html=True)
            st.markdown('<p class="cs-label">Hash Candidates</p>', unsafe_allow_html=True)
            rows_h = "".join(
                f'<div class="h-row">'
                f'<span class="badge {"b-high" if c.confidence=="High" else "b-medium" if c.confidence=="Medium" else "b-low"}">'
                f'{c.confidence}</span>'
                f'<span class="h-algo">{c.algorithm}</span>'
                f'<span class="h-note">— {c.note}</span>'
                f'</div>'
                for c in hash_candidates
            )
            st.markdown(f"""
            <div class="cs-card-warn">
              <div style="font-size:0.8rem;font-weight:700;color:{WARN};margin-bottom:0.7rem">
                #️⃣&nbsp; Hash detected — identification only, no cracking performed
              </div>
              {rows_h}
            </div>
            """, unsafe_allow_html=True)

# ── Tip bar ────────────────────────────────────────────────────────────────────
st.markdown(
    f'<div class="cs-tip">'
    f'💡 Try: <code>SGVsbG8gV29ybGQ=</code> · <code>48656c6c6f</code> · '
    f'<code>hello%20world</code> · <code>Uryyb</code>'
    f'</div>',
    unsafe_allow_html=True,
)
