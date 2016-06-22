#!/bin/bash
openssl genrsa -out minion-key.pem 2048
openssl req -new -key minion-key.pem -out minion.csr -subj "/CN=minion" -config minion-openssl.cnf
openssl x509 -req -in minion.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out minion.pem -days 9999 -extensions v3_req -extfile minion-openssl.cnf
