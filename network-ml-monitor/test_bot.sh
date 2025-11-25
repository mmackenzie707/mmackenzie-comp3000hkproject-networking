#!/bin/bash
echo "Generating bot traffic..."
for i in {1..100}; do
  curl -s -H "User-Agent: MaliciousBot/1.0" \
       http://localhost:5000/api/login -X POST \
       -d "{\"username\":\"attack_$i\",\"password\":\"test\"}" > /dev/null &
  sleep 0.1
done
wait
echo "Bot traffic complete"
