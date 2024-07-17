#!/bin/bash

URL="http://k8s-frontend-frontend-c8ca711d35-2027387127.us-west-2.elb.amazonaws.com/transaction"
NUM_REQUESTS=10000
PARALLELISM=3000 # Number of parallel requests to make

seq $NUM_REQUESTS | xargs -n1 -P$PARALLELISM -I{} curl -s -o /dev/null -w "%{http_code}\n" $URL
