#!/bin/bash
# We pack the configuration templates using go-bindata.
# go get -u go-bindata.  This is included in our binary as bindata.go.  For now we include this file in the source checkout also.
rm bindata.go ||true
go-bindata templates/ k8s_certs/*.sh config/
