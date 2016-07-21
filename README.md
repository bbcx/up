## K8S Up

Management of K8S on AWS.

## Requirements
* [install kubectl](http://kubernetes.io/docs/user-guide/prereqs/) but don't worry about configuring it.  Up will take care of that.

## Quick Install

```
git clone https://github.com/bbcx/up
cd up
go get
go build up.go bindata.go
# Modify the config and change the settings that say CHANGEME
cp config.toml.example config.toml
```

## Configure for AWS Region
If you're in a different region than us-west-2 choose the AMI for your region from the latest [release](https://blackbird.cx/post/blackbirdos-releases.html).

## Launching K8S
```
./up -action=init
```

## Adding a Minion to the cluster
```
./up -action=launch-minion
```

## Deleting K8S
```
./up -action=delete
```
