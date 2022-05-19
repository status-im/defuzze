#!/bin/sh
curl -H "Content-Type: application/json" -d "{\"username\": \"Defuzze\", \"content\": \"Failure of $TARGET/$BINARY\nRepro: $REPRO - $FILE\"}" $1
