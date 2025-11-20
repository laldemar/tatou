# tatou
A web platform for pdf watermarking. This project is intended for pedagogical use, and contain security vulnerabilities. Do not deploy on an open network.

### Report
All project artifacts are stored in a shared Google Drive folder for accessibility and verification purposes.

The folder is organised per group member and contains logs, test results, and supporting files that demonstrate each specialisation’s outputs

## Instructions

The following instructions are meant for a bash terminal on a Linux machine. If you are using something else, you will need to adapt them.

To clone the repo, you can simply run:

```bash
git clone https://github.com/nharrand/tatou.git
```

Note that you should probably fork the repo and clone your own repo.


### RMAP
TO be able to run rmap and get other groups pds you need to first activate the virutal environment:

. .venv/bin/activate 

This needs to be done when you are in ~/Desktop/tatou/

From there you run:

python -m rmap.rmap_client \
  --server 10.11.202.x \
  --identity Group_05 \
  --client-priv server/Group_05_passwordless_private.asc \
  --server-pub server/keys/clients/Group_x.asc \
  --outdir rmap_pdf


Test locally:
rmap-client --server 127.0.0.1  \
--identity Group_05  \
--client-priv server/Group_05_passwordless_private.asc \
--server-pub server/keys/server_public.asc
--outdir rmap_pdf


### Fuzzing
## Run
1) Start Tatou in the VM (docker compose up -d).
2) . .venv/bin/activate - from ~/Desktop/tatou
3) pip install -r fuzz/requirements.txt
4) Run:        TATOU_BASE_URL=http://localhost:5000 pytest server/fuzz -q
   (or change BASE_URL if you expose the port to host)

- Uses Hypothesis to generate HTTP payloads.
- Any 5xx or crash/hang is a bug.
- Keep any failing minimized inputs as regression tests in server/src/test/.
- pip install -r fuzz/requirements.txt
- TATOU_BASE_URL=http://localhost:5000 pytest fuzz -q

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

## Unit test
. .venv/bin/activate

sudo docker compose up -d db

export DB_HOST=127.0.0.1
export DB_PORT=3306
export DB_USER=tatou
export DB_PASSWORD=******
export DB_NAME=tatou
pytest --cov=server --cov-report=html

To run the unit test. activate the virtual environment. In tatou

. .venv/bin/activate 

pytest --cov=server --cov-report=html

