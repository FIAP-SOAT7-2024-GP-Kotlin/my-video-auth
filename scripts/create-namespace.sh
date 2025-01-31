#!/bin/bash
PROJECT_ID=1f3e6919-579f-400b-9dab-a6dafaaaafa7
PROJECT_NAME=first-project
NAMESPACE_NAME=authentication-namespace

echo "Creating namespace - $NAMESPACE_NAME"
doctl serverless namespaces create --label $NAMESPACE_NAME --region "nyc1"
