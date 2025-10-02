from hypothesis import strategies as st

# valid-ish PDF bytes (small; avoids Hypothesis draw function mistakes)
def pdf_bytes():
    prefix = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
    suffix = b"\n%%EOF\n"
    return st.binary(min_size=0, max_size=2000).map(lambda b: prefix + b + suffix)

# keep “name” filesystem/DB-friendly so we can exercise later endpoints
safe_char = st.characters(
    blacklist_categories=["Cs", "Cc", "Zl", "Zp", "Zs"],
    blacklist_characters=["/", "\\", "\x00"]
)
safe_name = st.text(safe_char, min_length=1, max_length=60)

weird_str = st.text(min_length=0, max_length=60)

positions = st.sampled_from(["", "topleft", "topright", "bottomleft", "bottomright", "center"])
