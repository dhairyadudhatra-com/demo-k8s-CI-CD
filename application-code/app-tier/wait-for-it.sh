#!/bin/sh
cmd="$@"
while ! nc -z -v $DB_HOST $DB_PORT; do
  sleep 1
done
echo "MYSQL started..."
exec $cmd