from hypothesis import strategies as st

def pdf_bytes():
    prefix = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
    suffix = b"\n%%EOF\n"
    return st.binary(min_size=0, max_size=2000).map(lambda b: prefix + b + suffix)

# Filesystem-safe-ish characters
safe_char = st.characters(
    blacklist_categories=["Cs", "Cc", "Zl", "Zp", "Zs"],
    blacklist_characters=["/", "\\", "\x00"],
)

# USE min_size / max_size with your Hypothesis version
safe_name = st.text(safe_char, min_size=1, max_size=60)
weird_str = st.text(min_size=0, max_size=60)

positions = st.sampled_from(
    ["", "topleft", "topright", "bottomleft", "bottomright", "center"]
)
