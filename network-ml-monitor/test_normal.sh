#!/bin/bash
echo "Generating normal traffic..."
for i in {1..20}; do
  curl -s http://localhost:5000/api/data > /dev/null
  curl -s http://localhost:5000/api/users > /dev/null
  sleep 5  # Realistic user delay
done
echo "Normal traffic complete"
