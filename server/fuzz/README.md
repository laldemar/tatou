# Tatou API fuzzer

## Run
1) Start Tatou in the VM (docker compose up -d).
2) In the VM:  pip install -r fuzz/requirements.txt
3) Run:        TATOU_BASE_URL=http://localhost:5000 pytest fuzz -q
   (or change BASE_URL if you expose the port to host)

## Notes
- Uses Hypothesis to generate HTTP payloads.
- Any 5xx or crash/hang is a bug.
- Keep any failing minimized inputs as regression tests in server/src/test/.
- pip install -r fuzz/requirements.txt
- TATOU_BASE_URL=http://localhost:5000 pytest fuzz -q