## K8S Up

Management of K8S on AWS.

## Quick Install

```
git clone https://github.com/bbcx/up
cd up
go get
go build up.go bindata.go
# Modify the config and change the settings that say CHANGEME
cp config.toml.example config.toml
```

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

