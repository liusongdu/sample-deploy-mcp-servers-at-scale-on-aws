python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cdk deploy --all --require-approval never --profile leo@539247484506