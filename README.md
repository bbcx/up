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
``` 

## Launching K8S
```
./up -action=init
```

## Configuration
Up can manage multiple clusters.  The first cluster you launch will be called "launch-default"

All configuration files, templates and ssl certificates for the clusters are stored in ```$HOME/.launch/```

Up will take care of picking configuration values automatically when you init a new cluster.  In the event you need to configure things (such as the VPC cidrs) the configuration can be found in ```$HOME/.launch/<NAME OF CLUSTER>/config/config.toml```  

At this time, it's best to run the init and let it fail if the CIDR needs config.  *then edit the config.

## Adding Minion(s) to the cluster
The number of minions launched and type of instance is determined by the configuration at $HOME/.launch/<NAME OF CLUSTER>/config/config.toml

```
# Minion Cluster Size
minion-cluster-size="1"
minion-instance-type="t2.micro"
```

```
./up -action=launch-minion
```

## Parking K8S
With Up you can simply terminate the instances but leave all the aws resources.  This speeds up the process re-upping.

```
./up -action=park
```

## Deleting K8S
```
./up -action=delete
```

## K8S Architecture Diagram
```
                   Public Internet
                        ^
                        |
                        |
                        |
                        |
                        |
                      +-+---------------------------------+
                      |      Internet Gateway (IGW)       +^---------------------------------------------------------+
                      |                                   |                                                          |
                      +-^---------------------------------+                                                          |
                        |                                                                                            |
+--------------------------------------------------------------------------------------------------+-------------------------------------------------------------+
|K8S VPC                |                                     |1 Route Table. 3 Subnets.           |                 |                                           |
|             +---------+----------+                          +------------------------------------+      +----------+---------+                                 |
|             |Master ELB          |                                                                      |    Service 1 ELB   +-----------------------------+   |
|             +---------^----------+-                                                                     +--------------------+                             |   |
|                                |ELB -> Master API 6443                                                                                                     |   |
|     +-------------------------------------------------------------+                                   +--------------------------------------------------+ |   |
|     |Master Security Group     |                                  |                                   |Minion Security Group                             | |   |
|     |           +--------------+---+------------------+           |                                   |                                                  | |   |
|     |           |                  |                  |           |                                   |  +--------------------+    +------------------+  | |   |
|     |   +-------v-------+  +-------v--------+  +------v--------+  |   Minion access from Master       |  |Minion 1            |    |Minion 2          |  | |   |
|     |   |Master 1       |  |Master 2        |  |Master 3       |  +-------------SSL-----------------> |  |  * kubelet         |    |  * kubelet       |  | |   |
|     |   |               |  |                |  |               |  |                                   |  |  * kube-proxy <----------+ * kube-proxy<--------+   |
|     |   | * K8S api     |  | * K8S api      |  | * K8S api     |  |    Master API access on 6443      |  |                    |    |                  |  |     |
|     |   | * etcd        |  | * etcd         |  | * etcd        |  | <------------SSL------------------+  |         |          |    |      |           |  |     |
|     |   | * K8S Manager |  | * K8S manager  |  | * K8S manager |  |                                   |  |         |          |    |      |           |  |     |
|     |   |               |  |                |  |               |  |                                   |  |         |          |    |      |           |  |     |
|     |   |               |  |                |  |               |  |                                   |  |         |          |    |      |           |  |     |
|     |   +---------------+  +----------------+  +---------------+  |                                   |  +----------- --------+    +------------------+  |     |
|     |                                                             |                                   |            |                      |              |     |
|     |                                                             |                                   |          +-v-----------    -------v----+         |     |
|     |                                                             |                                   |          |Service 1: type LoadBalancer |         |     |
|     |                                                             |                                   |          |                             |         |     |
|     |                                                             |                                   |          +--------------+--------------+         |     |
|     |                                                             |                                   |                         |                        |     |
|     |                                                             |                                   |          +--------------v--------------+         |     |
|     |                                                             |                                   |          |Deployment 1                 |         |     |
|     |                                                             |                                   |          +-----------------------------+         |     |
|     |                                                             |                                   |                                                  |     |
|     +-------------------------------------------------------------+                                   +--------------------------------------------------+     |
|                                                                                                                                                                |
|                                                                                                                                                                |
|                                                                                                                                                                |
|                                                                                                                                                                |
+----------------------------------------------------------------------------------------------------------------------------------------------------------------+
```
