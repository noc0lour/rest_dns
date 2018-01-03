#!/bin/sh

# Get JWT token
KEY=$(curl localhost:5000/auth --data '{ "username": "test1", "password": "test" }' -H "Content-Type: application/json" 2>/dev/null | jq -r .access_token)

# Access restricted resource
RET=$(curl -H "Authorization: JWT ${KEY}" localhost:5000/api/v1/example.com/test.example.com --data '{ "request_type": "add", "ttl": "1200", "type": "AAAA", "target": "::1" }' 2>/dev/null)
echo "${RET}"

