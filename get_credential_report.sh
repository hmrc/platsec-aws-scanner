#!/usr/bin/env bash

set_aws_credentials() {
  STS=$(
		aws-vault exec auth -- aws sts assume-role \
			--role-arn "${ASSUME_ROLE_ARN}" \
			--role-session-name "${SESSION_NAME}" \
			--query "Credentials" 2>&1
	)

  SEARCH="error"
  if [[ "${STS}" =~ $SEARCH ]]; then
    echo "ERROR"
    echo $ACCOUNT
    AWS_ACCESS_KEY_ID="ERROR"
    AWS_SECRET_ACCESS_KEY="ERROR"
    AWS_SESSION_TOKEN="ERROR"
  else
    AWS_ACCESS_KEY_ID="$(jq -r '.AccessKeyId' <<<"${STS}")"
    AWS_SECRET_ACCESS_KEY="$(jq -r '.SecretAccessKey' <<<"${STS}")"
    AWS_SESSION_TOKEN="$(jq -r '.SessionToken' <<<"${STS}")"
  fi

  export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
}

ACCOUNTS=( $(echo $(aws-vault exec root-RolePlatformReadOnly -- aws organizations list-accounts) | jq -r '.Accounts[].Id'));
ERRORS=()
for ACCOUNT in "${ACCOUNTS[@]}"; do
    ASSUME_ROLE_ARN=arn:aws:iam::${ACCOUNT}:role/RolePlatformReadOnly SESSION_NAME="cred-report-${ACCOUNT}" set_aws_credentials
    
    if [[ "${AWS_ACCESS_KEY_ID}" == "ERROR" ]]; then 
      echo "ERROR"
      echo $ACCOUNT
      continue
    fi

    while [[ $(aws iam generate-credential-report | tee | jq -r '.State') != "COMPLETE" ]]; do
      sleep 5
    done

    REPORT=$(aws iam get-credential-report --output json | tee | jq -r '.Content' | base64 -d)
    if [[ $REPORT ]]; then
      echo "${REPORT}" > "reports/${ACCOUNT}-report.csv"
    else
      ERRORS+=($ACCOUNT)
    fi
done

printf "%s\n" "${ERRORS[@]}" > "reports/zzz-unauthorised-accounts-report-errors.txt"