#!/bin/bash

# Generate private key
openssl genpkey -algorithm RSA -out private_key.pem

# Extract public key from private key
openssl rsa -pubout -in private_key.pem -out public_key.pem

echo "Public and private keys generated successfully."
