source .venv/bin/activate
cdk destroy --all --require-approval never --profile leo@539247484506
#rm -rf .venv
rm -rf cdk.out
