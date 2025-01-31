#!/bin/bash
PROJECT_ID=a6c0754c-a2bd-41e4-b40a-85ebbc0efd1d
PROJECT_NAME=first-project
NAMESPACE_ID=fn-40807b32-b98c-439f-8bd7-99d62dcc3994

# List namespaces
doctl serverless namespaces list

# Label                       Region    Namespace ID                               API Host
# authentication-namespace    nyc1      fn-40807b32-b98c-439f-8bd7-99d62dcc3994    https://faas-nyc1-2ef2e6cc.doserverless.co


# Connect to project's target namespace
echo "Connecting to namespace - $NAMESPACE_ID"
doctl serverless connect $NAMESPACE_ID

echo "Deploying function"
doctl serverless deploy ../ --remote-build
