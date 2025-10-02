from hypothesis import strategies as st
import base64

# “Weird” text to hit edge cases
weird_str = st.one_of(
    st.text(min_size=0, max_size=200),
    st.from_regex(r"[<>\'\"`;()\\/\x00%]", fullmatch=False),
    st.sampled_from(["", ".", "..", "../", "../../../../etc/passwd"])
)

email_str = st.emails()

def pdf_bytes():
    def build(draw):
        good = draw(st.booleans())
        body = draw(st.binary(min_size=0, max_size=4096))
        if good:
            return b"%PDF-1.4\n" + body + b"\n%%EOF\n"
        return body
    return st.builds(build)

b64ish = st.binary(min_size=0, max_size=1500).map(lambda b: base64.b64encode(b).decode("ascii"))
