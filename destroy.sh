source .venv/bin/activate
cdk destroy --all --require-approval never
rm -rf .venv
rm -rf cdk.out
