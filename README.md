# tatou
A web platform for pdf watermarking. This project is intended for pedagogical use, and contain security vulnerabilities. Do not deploy on an open network.

### Report
All project artifacts are stored in a shared Google Drive folder for accessibility and verification purposes.

The folder is organised per group member and contains logs, test results, and supporting files that demonstrate each specialisation’s outputs.

## Instructions

The following instructions are meant for a bash terminal on a Linux machine. If you are using something else, you will need to adapt them.

To clone the repo, you can simply run:

```bash
git clone https://github.com/nharrand/tatou.git
```

Note that you should probably fork the repo and clone your own repo.

### Fuzzing
## Run
1) Start Tatou in the VM (docker compose up -d).
2) In the VM:  pip install -r fuzz/requirements.txt
3) Run:        TATOU_BASE_URL=http://localhost:5000 pytest fuzz -q
   (or change BASE_URL if you expose the port to host)

- Uses Hypothesis to generate HTTP payloads.
- Any 5xx or crash/hang is a bug.
- Keep any failing minimized inputs as regression tests in server/src/test/.
- pip install -r fuzz/requirements.txt
- TATOU_BASE_URL=http://localhost:5000 pytest fuzz -q

# rmap
export CLIENT_PASSPHRASE='your-Group_05-private-key-pass'

python server/get_rmap.py 10.11.202.x --port 5000 \
  --identity Group_x \
  --server-pub server/keys/clients/Group_x.asc \
  --outdir rmap_pdf

### Run python unit tests

```bash
cd tatou/server

# Create a python virtual environement
python3 -m venv .venv

# Activate your virtual environement
. .venv/bin/activate

# Install the necessary dependencies
python -m pip install -e ".[dev]"

# Run the unit tests
python -m pytest
```

### Deploy

From the root of the directory:

```bash
# Create a file to set environement variables like passwords.
cp sample.env .env

# Edit .env and pick the passwords you want

# Rebuild the docker image and deploy the containers
docker compose up --build -d

# Monitor logs in realtime 
docker compose logs -f

# Test if the API is up
http -v :5000/healthz

# Open your browser at 127.0.0.1:5000 to check if the website is up.
```

## Mutation Testing Summary
Mutation testing was executed successfully in an isolated environment (mini-mut).  
All four generated mutants were killed by the tests, confirming the test setup works.  
In the main project, MutMut could not collect stats due to complex path dependencies.  
See `mutmut_isolated_results.pdf` and `pytest_roundtrip_output.pdf` for details.

