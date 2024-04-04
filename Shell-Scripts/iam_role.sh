#!/usr/bin/env bash 

TRUST_CODEBUILD="{   \"Version\": \"2012-10-17\",   \"Statement\": [     {       \"Effect\": \"Allow\",       \"Principal\": {         \"Service\": \"codebuild.amazonaws.com\"       },       \"Action\": \"sts:AssumeRole\"     }   ] }"
aws iam create-role --role-name AWS-DevSecOps-Netflix-CB-Role --assume-role-policy-document "$TRUST_CODEBUILD" --output text --query 'Role.Arn'
aws iam put-role-policy --role-name AWS-DevSecOps-Netflix-CB-Role --policy-name AWS-DevSecOps-Netflix-CB-Policy --policy-document file://codebuildpolicy.json

TRUST_CODEPIPELINE="{   \"Version\": \"2012-10-17\",   \"Statement\": [     {       \"Effect\": \"Allow\",       \"Principal\": {         \"Service\": \"codepipeline.amazonaws.com\"       },       \"Action\": \"sts:AssumeRole\"     }   ] }"
aws iam create-role --role-name AWS-DevSecOps-Netflix-CP-Role --assume-role-policy-document "$TRUST_CODEPIPELINE" --output text --query 'Role.Arn'
aws iam put-role-policy --role-name AWS-DevSecOps-Netflix-CP-Role --policy-name AWS-DevSecOps-Netflix-CP-Policy --policy-document file://codepipelinepolicy.json

TRUST_LAMBDA="{   \"Version\": \"2012-10-17\",   \"Statement\": [     {       \"Effect\": \"Allow\",       \"Principal\": {         \"Service\": \"lambda.amazonaws.com\"       },       \"Action\": \"sts:AssumeRole\"     }   ] }"
aws iam create-role --role-name AWS-DevSecOps-Netflix-LF-Role --assume-role-policy-document "$TRUST_LAMBDA" --output text --query 'Role.Arn'
aws iam put-role-policy --role-name AWS-DevSecOps-Netflix-LF-Role --policy-name AWS-DevSecOps-Netflix-LF-Policy --policy-document file://lambdafuncpolicy.json