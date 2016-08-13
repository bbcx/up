package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/elb"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/spf13/viper"
)

type templateValuesForUserData struct {
	ServiceClusterIPRange string
	ClusterDNS            string
	ClusterCIDR           string
	ClusterName           string
	ELBDNSName            string
	Discovery             string
	SSLStorageBucket      string
}

type sslConf struct {
	WorkerIP   string
	ELBDNSName string
}

type userKubeConfig struct {
	MasterURL         string
	CertAuthorityPath string
	ClientCertPath    string
	ClientKeyPath     string
}

type policyConf struct {
	S3Bucket    string
	ClusterName string
}

func ensureRouteTable(svc *ec2.EC2) (success bool) {

	// Lookup existing resources from tag name
	var ourTag = viper.GetString("cluster-name")

	// Lookup route table (just to ensure it exists)
	params := &ec2.DescribeRouteTablesInput{
		Filters: []*ec2.Filter{
			{
				Name: aws.String("tag:KubernetesCluster"),
				Values: []*string{
					aws.String(ourTag),
				},
			},
		},
	}
	resp, err := svc.DescribeRouteTables(params)

	if err != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(err.Error())
		return false
	}

	// Pretty-print the response data.
	if len(resp.RouteTables) == 0 {
		return false
	}

	//fmt.Println(resp)
	return true
}

func deleteSecGroupsExtra(svc *ec2.EC2) {
	params := &ec2.DescribeSecurityGroupsInput{
		Filters: []*ec2.Filter{
			{ // Required
				Name: aws.String("tag:KubernetesCluster"),
				Values: []*string{
					aws.String(viper.GetString("cluster-name")),
				},
			},
		},
	}
	resp, err := svc.DescribeSecurityGroups(params)

	if err != nil {
		fmt.Println(err.Error())
	}

	if len(resp.SecurityGroups) == 0 {
		return
	}

	for i := range resp.SecurityGroups {
		stripSecGroup(svc, resp.SecurityGroups[i].GroupId)
		fmt.Print("deleting security groups created by k8s services ")
		deleteSecGroup(svc, resp.SecurityGroups[i].GroupId, 0)
		fmt.Println()
	}
}

func getSecurityGroup(svc *ec2.EC2, kindOf string) *string {
	params := &ec2.DescribeSecurityGroupsInput{
		Filters: []*ec2.Filter{
			{ // Required
				Name: aws.String("tag:KubernetesCluster"),
				Values: []*string{
					aws.String(viper.GetString("cluster-name")),
				},
			},
			{ // Required
				Name: aws.String("tag:for"),
				Values: []*string{
					aws.String(kindOf),
				},
			},
		},
	}
	resp, err := svc.DescribeSecurityGroups(params)

	if err != nil {
		fmt.Println(err.Error())
	}

	if len(resp.SecurityGroups) == 0 {
		return nil
	}

	return resp.SecurityGroups[0].GroupId
}

func getSubnets(svc *ec2.EC2) (subnetID *string) {
	params := &ec2.DescribeSubnetsInput{
		Filters: []*ec2.Filter{
			{
				Name: aws.String("tag:KubernetesCluster"),
				Values: []*string{
					aws.String(viper.GetString("cluster-name")),
				},
			},
		},
	}
	resp, err := svc.DescribeSubnets(params)

	if err != nil {
		fmt.Println("error during getSubnets!")
		fmt.Println(err.Error())
		return nil
	}

	if len(resp.Subnets) == 0 {
		fmt.Println("error during getSubnets, zero subnets found!")
		return nil
	}

	return resp.Subnets[0].SubnetId
}

func getDNSName(svc *elb.ELB) *string {

	lookupName := viper.GetString("elb-name")

	params := &elb.DescribeLoadBalancersInput{
		LoadBalancerNames: []*string{
			aws.String(lookupName),
		},
		//Marker:   aws.String("Marker"),
		//PageSize: aws.Int64(1),
	}
	resp, err := svc.DescribeLoadBalancers(params)

	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	return resp.LoadBalancerDescriptions[0].DNSName
}

func getLatestAmi() string {
	resp, err := http.Get(viper.GetString("ami-update-url") + viper.GetString("region"))
	if err != nil {
		fmt.Println("Error: Could not get latest ami")
		return ""
	}
	defer resp.Body.Close()
	//body, err := ioutil.ReadAll(resp.Body)

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)

	s := buf.String()
	return s
}

func getEtcdDiscoveryService(size string) string {
	resp, err := http.Get("https://discovery.etcd.io/new?size=" + size)
	if err != nil {
		panic("Could not get etcd discovery token from discovery.etcd.io")
	}
	defer resp.Body.Close()
	//body, err := ioutil.ReadAll(resp.Body)

	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)

	s := buf.String()
	return s
}

func generatePolicyFromTemplate(templateFileName string, templateValues policyConf) string {
	templateText, err := ioutil.ReadFile(templateFileName)
	tmpl, err := template.New("policyConf").Parse(string(templateText))
	if err != nil {
		panic(err)
	}
	var dataBytesBuffer bytes.Buffer
	err = tmpl.Execute(&dataBytesBuffer, templateValues)
	if err != nil {
		panic(err)
	}
	return dataBytesBuffer.String()
}

// Render user-data to a string using the specified template
func generateUserDataFromTemplate(templateFileName string, templateValues templateValuesForUserData) string {
	templateText, err := ioutil.ReadFile(templateFileName)
	tmpl, err := template.New("user-data").Parse(string(templateText))
	if err != nil {
		panic(err)
	}
	var userDataBytesBuffer bytes.Buffer
	err = tmpl.Execute(&userDataBytesBuffer, templateValues)
	if err != nil {
		panic(err)
	}
	return userDataBytesBuffer.String()
}

func assocMasterWithELB(svc *elb.ELB, instanceID *string) {
	params := &elb.RegisterInstancesWithLoadBalancerInput{
		Instances: []*elb.Instance{
			{
				InstanceId: instanceID,
			},
		},
		LoadBalancerName: aws.String(viper.GetString("elb-name")),
	}
	_, err := svc.RegisterInstancesWithLoadBalancer(params)

	if err != nil {
		fmt.Println(err.Error())
		panic("Fatal: Could not register master with ELB.")
	}
}

func launchMaster(svc *ec2.EC2, userData string, instanceProfileArn string, vpcID *string) *string {
	masterSecurityGroupID := getSecurityGroup(svc, "Master")

	if masterSecurityGroupID == nil {
		masterSecurityGroupID = createSecurityGroup(svc, "Master", vpcID)
	}

	subnetID := getSubnets(svc)

	if subnetID == nil {
		panic("Fatal: could not lookup subnetID for this cluster.")
	}

	params := &ec2.RunInstancesInput{
		ImageId:  aws.String(viper.GetString("ami")),
		MaxCount: aws.Int64(1),
		MinCount: aws.Int64(1),
		//EbsOptimized:          aws.Bool(true),
		IamInstanceProfile: &ec2.IamInstanceProfileSpecification{
			//Arn: aws.String(instanceProfileArn),
			Name: aws.String("k8s-master" + viper.GetString("cluster-name")),
		},
		InstanceInitiatedShutdownBehavior: aws.String("terminate"),
		InstanceType:                      aws.String(viper.GetString("master-instance-type")),
		KeyName:                           aws.String(viper.GetString("ssh-key-name")),
		SecurityGroupIds: []*string{
			masterSecurityGroupID,
		},
		SubnetId: subnetID,
		UserData: aws.String(userData),
	}
	resp, err := svc.RunInstances(params)

	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	tagIt(svc, resp.Instances[0].InstanceId)
	tagName(svc, resp.Instances[0].InstanceId, "k8sMaster-"+viper.GetString("cluster-name"))
	// Pretty-print the response data
	return resp.Instances[0].InstanceId
}

// Add KubernetesCluster=<clustername> tag to a resource
func tagIt(svc *ec2.EC2, ID *string) bool {
	time.Sleep(10)
	_, errtag := svc.CreateTags(&ec2.CreateTagsInput{
		Resources: []*string{ID},
		Tags: []*ec2.Tag{
			{
				Key:   aws.String("KubernetesCluster"),
				Value: aws.String(viper.GetString("cluster-name")),
			},
		},
	})
	if errtag != nil {
		fmt.Println("Could not create tags for ", *ID, errtag)
		return false
	}
	return true
}

func tagFor(svc *ec2.EC2, ID *string, tagFor string) bool {
	time.Sleep(10)
	_, errtag := svc.CreateTags(&ec2.CreateTagsInput{
		Resources: []*string{ID},
		Tags: []*ec2.Tag{
			{
				Key:   aws.String("for"),
				Value: aws.String(tagFor),
			},
		},
	})
	if errtag != nil {
		fmt.Println("Could not create tags for ", *ID, errtag)
		return false
	}
	return true
}

// Add Name= tag to a resource
func tagName(svc *ec2.EC2, ID *string, name string) bool {
	_, errtag := svc.CreateTags(&ec2.CreateTagsInput{
		Resources: []*string{ID},
		Tags: []*ec2.Tag{
			{
				Key:   aws.String("Name"),
				Value: aws.String(name),
			},
		},
	})
	if errtag != nil {
		fmt.Println("Could not create tags for ", *ID, errtag)
		return false
	}
	return true
}

func launchMinion(svc *ec2.EC2, userData string, instanceProfileArn string, vpcID *string) (*string, *string) {
	securityGroupID := getSecurityGroup(svc, "Minion")

	if securityGroupID == nil {
		securityGroupID = createSecurityGroup(svc, "Minion", vpcID)
	}

	subnetID := getSubnets(svc)

	if subnetID == nil {
		panic("Fatal: could not lookup subnetID for this cluster.")
	}

	params := &ec2.RunInstancesInput{
		ImageId:  aws.String(viper.GetString("ami")),
		MaxCount: aws.Int64(1),
		MinCount: aws.Int64(1),
		//EbsOptimized:          aws.Bool(true),
		BlockDeviceMappings: []*ec2.BlockDeviceMapping{
			{ // Required
				DeviceName: aws.String("/dev/sda1"),
				Ebs: &ec2.EbsBlockDevice{
					DeleteOnTermination: aws.Bool(true),
					//Iops:                aws.Int64(1),
					VolumeSize: aws.Int64(int64(viper.GetInt("minion-root-volume-size"))),
				},
			},
		},
		IamInstanceProfile: &ec2.IamInstanceProfileSpecification{
			//Arn: aws.String(instanceProfileArn),
			Name: aws.String("k8s-minion" + viper.GetString("cluster-name")),
		},
		InstanceInitiatedShutdownBehavior: aws.String("terminate"),
		InstanceType:                      aws.String(viper.GetString("minion-instance-type")),
		KeyName:                           aws.String(viper.GetString("ssh-key-name")),
		SecurityGroupIds: []*string{
			securityGroupID,
		},
		SubnetId: subnetID,
		UserData: aws.String(userData),
	}
	resp, err := svc.RunInstances(params)

	if err != nil {
		fmt.Println(err.Error())
		return nil, nil
	}

	tagIt(svc, resp.Instances[0].InstanceId)
	tagName(svc, resp.Instances[0].InstanceId, "k8sMinion-"+viper.GetString("cluster-name"))

	return resp.Instances[0].PrivateIpAddress, resp.Instances[0].InstanceId
}

func createS3Bucket() {
	svc := s3.New(session.New(), &aws.Config{Region: aws.String(viper.GetString("region"))})
	params := &s3.CreateBucketInput{
		Bucket: aws.String(viper.GetString("s3-ca-storage-bucket")),
		//ACL:    aws.String("BucketCannedACL"),
		CreateBucketConfiguration: &s3.CreateBucketConfiguration{
			LocationConstraint: aws.String(viper.GetString("region")),
		},
		//GrantFullControl: aws.String("GrantFullControl"),
		//GrantRead:        aws.String("GrantRead"),
		//GrantReadACP:     aws.String("GrantReadACP"),
		//GrantWrite:       aws.String("GrantWrite"),
		//GrantWriteACP:    aws.String("GrantWriteACP"),
	}
	_, err := svc.CreateBucket(params)

	if err != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(err.Error())
		//fmt.Println("S3 bucket already exists.  Continuing.")
		return
	}
}

func putObjS3(key string, content string) (success bool) {
	svc := s3.New(session.New(), &aws.Config{Region: aws.String(viper.GetString("region"))})

	params := &s3.PutObjectInput{
		Bucket: aws.String(viper.GetString("s3-ca-storage-bucket")), // Required
		Key:    aws.String(key),                                     // Required
		Body:   bytes.NewReader([]byte(content)),
	}
	_, err := svc.PutObject(params)

	if err != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(err.Error())
		return false
	}
	return true
}

func generateSkyDNSConfig(kubeConfigValues userKubeConfig) {
	targetFileName := "kube-dns-" + viper.GetString("cluster-name") + ".yaml"

	templateText, err := ioutil.ReadFile(path.Join(viper.GetString("template-path"), "kube_dns.yaml.template"))
	tmpl, err := template.New("kubedns").Parse(string(templateText))
	if err != nil {
		panic(err)
	}

	f, err := os.Create(targetFileName)
	if err != nil {
		fmt.Println("create file: ", err)
		panic("could not write file")
	}

	err = tmpl.Execute(f, kubeConfigValues)
	if err != nil {
		panic(err)
	}
	f.Close()
	fmt.Println("skydns config written to " + targetFileName)

}

func generateUserLaptopKubeConfig(kubeConfigValues userKubeConfig) {
	templateText, err := ioutil.ReadFile(path.Join(viper.GetString("template-path"), "dot-kube-config.template"))
	tmpl, err := template.New("userkube").Parse(string(templateText))
	if err != nil {
		panic(err)
	}

	f, err := os.Create(viper.GetString("kube-config-home"))
	if err != nil {
		fmt.Println("could not write to file", viper.GetString("kube-config-home"))
		fmt.Println("create file: ", err)
		panic("could not write file")
	}

	err = tmpl.Execute(f, kubeConfigValues)
	if err != nil {
		panic(err)
	}
	f.Close()
}

func generateSSL(fileTemplate string, sslSettings sslConf, generateCommand string, name string) (string, string, string) {
	// generate openssl.cnf template in the certs dir
	templateText, err := ioutil.ReadFile(fileTemplate)
	tmpl, err := template.New("opensslcnf").Parse(string(templateText))
	if err != nil {
		panic(err)
	}

	f, err := os.Create(viper.GetString("certificate-path") + "/" + name + "-openssl.cnf")
	if err != nil {
		fmt.Println("create file: ", err)
		panic("could not write file")
	}

	err = tmpl.Execute(f, sslSettings)
	if err != nil {
		panic(err)
	}
	f.Close()

	parentDir, _ := os.Getwd()

	os.Chdir(viper.GetString("certificate-path"))

	// generate the ca
	if _, err := os.Stat("ca.pem"); os.IsNotExist(err) {
		outCA, errExecCA := exec.Command("./generate_ca.sh").CombinedOutput()
		if errExecCA != nil {
			fmt.Println(errExecCA)
			fmt.Println(string(outCA))
			panic("Fatal: error occured while running ./generate_ca.sh")
		} else {
			fmt.Println("generated certificate authority using path: " + viper.GetString("certificate-path"))
		}
	}

	// generate admin keypair
	if _, errAdmin := os.Stat("admin.pem"); os.IsNotExist(errAdmin) {
		outAdmin, errExecAdmin := exec.Command("./generate_admin_keypair.sh").CombinedOutput()
		if errExecAdmin != nil {
			fmt.Println(errExecAdmin)
			fmt.Println(string(outAdmin))
			panic("Fatal: error occured while running ./generate_admin_keypair.sh")
		} else {
			fmt.Println("generated admin keypair using path: " + viper.GetString("certificate-path"))
		}
	}

	// generate master key with elb's name
	out, errExec := exec.Command(generateCommand).CombinedOutput()
	if errExec != nil {
		fmt.Println(errExec)
		fmt.Println(string(out))
		panic("Fatal: error occured while running" + generateCommand)
	} else {
		fmt.Println("run: " + generateCommand + " using path: " + viper.GetString("certificate-path"))
	}

	apiKey, apiKeyErr := ioutil.ReadFile(name + "-key.pem")
	if apiKeyErr != nil {
		panic(apiKeyErr)
	}

	apiPem, apiPemErr := ioutil.ReadFile(name + ".pem")
	if apiPemErr != nil {
		panic(apiPemErr)
	}

	ca, caErr := ioutil.ReadFile("ca.pem")
	if caErr != nil {
		panic(caErr)
	}

	os.Chdir(parentDir)
	return string(apiPem), string(apiKey), string(ca)
}

func deleteInstances(svc *ec2.EC2) bool {
	var ourTag = viper.GetString("cluster-name")
	// Instances with our cluster-name
	// Instances with a state != terminated
	params := &ec2.DescribeInstancesInput{
		Filters: []*ec2.Filter{
			{
				Name: aws.String("tag:KubernetesCluster"),
				Values: []*string{
					aws.String(ourTag),
				},
			},
			{
				Name: aws.String("instance-state-name"),
				Values: []*string{
					aws.String("running"),
					aws.String("pending"),
					aws.String("shutting-down"),
					aws.String("stopping"),
					aws.String("stopped"),
				},
			},
		},
	}
	resp, err := svc.DescribeInstances(params)

	if err != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(err.Error())
		return false
	}

	// Pretty-print the response data.
	if len(resp.Reservations) == 0 {
		return false
	}

	for i := 0; i < len(resp.Reservations); i++ {
		fmt.Println("terminating: " + *resp.Reservations[i].Instances[0].InstanceId)
		terminateInstance(svc, resp.Reservations[i].Instances[0].InstanceId)
	}
	for k := 0; k < len(resp.Reservations); k++ {
		fmt.Println("waiting for termination: " + *resp.Reservations[k].Instances[0].InstanceId)
		waitInstanceTerminated(svc, resp.Reservations[k].Instances[0].InstanceId)
	}
	return true
}

func terminateInstance(svc *ec2.EC2, instanceID *string) bool {
	params := &ec2.TerminateInstancesInput{
		InstanceIds: []*string{
			instanceID,
		},
	}

	_, err := svc.TerminateInstances(params)

	if err != nil {
		fmt.Println("Terminate instances failed.")
		fmt.Println(err)
		return false
	}

	return true
}

// Lookup vpc (just to ensure it exists)
func detectVPC(svc *ec2.EC2) (vpcID *string) {
	var ourTag = viper.GetString("cluster-name")
	params := &ec2.DescribeVpcsInput{
		Filters: []*ec2.Filter{
			{
				Name: aws.String("tag:KubernetesCluster"),
				Values: []*string{
					aws.String(ourTag),
				},
			},
		},
	}
	resp, err := svc.DescribeVpcs(params)

	if err != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(err.Error())
		return nil
	}

	if len(resp.Vpcs) == 0 {
		return nil
	}
	//fmt.Println(resp)
	return resp.Vpcs[0].VpcId
}

func createDhcpOptionsSet(svc *ec2.EC2) *string {
	useHostNameSuffix := ""
	if viper.GetString("region") == "us-east-1" {
		useHostNameSuffix = "ec2.internal"
	} else {
		useHostNameSuffix = ".compute.internal"
	}
	params := &ec2.CreateDhcpOptionsInput{
		DhcpConfigurations: []*ec2.NewDhcpConfiguration{
			{ // Required
				Key: aws.String("domain-name-servers"),
				Values: []*string{
					aws.String("AmazonProvidedDNS"), // Required
				},
			},
			{ // Required
				Key: aws.String("domain-name"),
				Values: []*string{
					aws.String(viper.GetString("region") + useHostNameSuffix), // Required
				},
			},
			//more
		},
	}

	resp, err := svc.CreateDhcpOptions(params)

	if err != nil {
		fmt.Println("error creating DHCP Options Set")
		fmt.Println(err)
		os.Exit(1)
	}

	tagIt(svc, resp.DhcpOptions.DhcpOptionsId)

	return resp.DhcpOptions.DhcpOptionsId
}

func vpcCheckConflict(svc *ec2.EC2) bool {
	// Todo we must paginate
	params := &ec2.DescribeVpcsInput{}
	resp, err := svc.DescribeVpcs(params)
	handleError(err, "Error describing VPCs")
	for i := range resp.Vpcs {
		if *resp.Vpcs[i].CidrBlock == viper.GetString("vpc-cidr-block") {
			fmt.Println("Error.  Conflicting VPC CIDR block detected.  In use by " + *resp.Vpcs[i].VpcId)
			usedConf := viper.ConfigFileUsed()
			fmt.Println("Please modify " + usedConf + " config to select a different cidr block and re-run.")
			return true
		}
	}
	return false
}

func createVPCNetworking(svc *ec2.EC2) *string {
	if vpcCheckConflict(svc) {
		fmt.Println("Exiting")
		os.Exit(1)
	}
	params := &ec2.CreateVpcInput{
		CidrBlock: aws.String(viper.GetString("vpc-cidr-block")), // Required
		//InstanceTenancy: aws.String("??"),
	}
	resp, err := svc.CreateVpc(params)

	if err != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(resp)
		fmt.Println(err.Error())
		os.Exit(1)
	}

	vpcID := resp.Vpc.VpcId

	fmt.Println("Created VPC: " + *vpcID)

	paramsModVPC := &ec2.ModifyVpcAttributeInput{
		VpcId: vpcID, // Required
		EnableDnsSupport: &ec2.AttributeBooleanValue{
			Value: aws.Bool(true),
		},
	}

	_, pModErr := svc.ModifyVpcAttribute(paramsModVPC)

	if pModErr != nil {
		fmt.Println("error modifying VPC attributes for DNS support")
		fmt.Println(pModErr)
		os.Exit(1)
	}

	paramsModVPC2 := &ec2.ModifyVpcAttributeInput{
		VpcId: vpcID, // Required
		EnableDnsHostnames: &ec2.AttributeBooleanValue{
			Value: aws.Bool(true),
		},
	}

	_, pModErr2 := svc.ModifyVpcAttribute(paramsModVPC2)

	if pModErr2 != nil {
		fmt.Println("error modifying VPC attributes for DNS hostnames")
		fmt.Println(pModErr2)
		os.Exit(1)
	}

	dhcpOptionsSetID := createDhcpOptionsSet(svc)
	paramsModVPC3 := &ec2.AssociateDhcpOptionsInput{
		VpcId:         vpcID,            // Required
		DhcpOptionsId: dhcpOptionsSetID, // Required
	}

	_, pModErr3 := svc.AssociateDhcpOptions(paramsModVPC3)

	if pModErr3 != nil {
		fmt.Println("error associating dhcp options set with VPC")
		fmt.Println(pModErr3)
		os.Exit(1)
	}

	rtParams := &ec2.DescribeRouteTablesInput{
		Filters: []*ec2.Filter{
			{
				Name: aws.String("vpc-id"),
				Values: []*string{
					vpcID,
				},
			},
		},
	}
	rtResp, rtErr := svc.DescribeRouteTables(rtParams)

	if rtErr != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(rtErr.Error())
		return nil
	}

	fmt.Println("Created route table: " + *rtResp.RouteTables[0].RouteTableId)

	// Tag the VPC and route tables
	tagIt(svc, vpcID)
	tagIt(svc, rtResp.RouteTables[0].RouteTableId)

	createSubnets(svc, vpcID)
	IGWID := addInternetGatewayToVPC(svc, vpcID)
	createRouteForIGW(svc, IGWID, rtResp.RouteTables[0].RouteTableId)

	return vpcID
}

func addInternetGatewayToVPC(svc *ec2.EC2, vpcID *string) *string {
	params := &ec2.CreateInternetGatewayInput{}
	resp, err := svc.CreateInternetGateway(params)
	if err != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(err.Error())
		os.Exit(1)
	}

	params2 := &ec2.AttachInternetGatewayInput{
		InternetGatewayId: resp.InternetGateway.InternetGatewayId, // Required
		VpcId:             vpcID,                                  // Required
	}
	_, err2 := svc.AttachInternetGateway(params2)

	if err2 != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(err2.Error())
		os.Exit(1)
	}
	tagIt(svc, resp.InternetGateway.InternetGatewayId)
	return resp.InternetGateway.InternetGatewayId
}

func createRouteForIGW(svc *ec2.EC2, IGWID *string, routeTableID *string) {
	params := &ec2.CreateRouteInput{
		DestinationCidrBlock: aws.String("0.0.0.0/0"), // Required
		RouteTableId:         routeTableID,            // Required
		GatewayId:            IGWID,
	}
	_, err := svc.CreateRoute(params)

	if err != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println("Error creating route for IGW.")
		fmt.Println(err.Error())
		os.Exit(1)
		return
	}
}

func createSubnets(svc *ec2.EC2, vpcID *string) {
	// Get the availability zones list
	descAZParams := &ec2.DescribeAvailabilityZonesInput{}
	descAZResp, descAZErr := svc.DescribeAvailabilityZones(descAZParams)

	if descAZErr != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(descAZErr.Error())
		return
	}
	//numAZs := int64(len(descAZResp.AvailabilityZones))

	// Create the subnets
	times, _ := strconv.ParseInt(viper.GetString("num-subnets"), 10, 0)
	var loop int64
	for loop = 0; loop < times; loop++ {
		//useAZIndex := loop % numAZs
		myCidrBlock := viper.GetString("subnet-" + fmt.Sprintf("%d", loop) + "-cidr")
		params := &ec2.CreateSubnetInput{
			CidrBlock:        aws.String(myCidrBlock),
			VpcId:            vpcID,
			AvailabilityZone: descAZResp.AvailabilityZones[loop].ZoneName,
		}
		resp, err := svc.CreateSubnet(params)

		if err != nil {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
			return
		}

		// Set auto-assign public IP on subnet
		params2 := &ec2.ModifySubnetAttributeInput{
			SubnetId: resp.Subnet.SubnetId,
			MapPublicIpOnLaunch: &ec2.AttributeBooleanValue{
				Value: aws.Bool(true),
			},
		}
		_, err2 := svc.ModifySubnetAttribute(params2)

		if err2 != nil {
			fmt.Println("Auto assign public IP failed for subnet.")
			fmt.Println(err.Error())
			os.Exit(1)
		}

		if err != nil {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Println(err.Error())
			return
		}

		// Tag the subnets
		_, errtag := svc.CreateTags(&ec2.CreateTagsInput{
			Resources: []*string{resp.Subnet.SubnetId},
			Tags: []*ec2.Tag{
				{
					Key:   aws.String("KubernetesCluster"),
					Value: aws.String(viper.GetString("cluster-name")),
				},
			},
		})
		if errtag != nil {
			log.Println("Could not create tags for subnet", *resp.Subnet.SubnetId, errtag)
			return
		}
	}
}

func deleteVPC(svc *ec2.EC2) {
	// Find the VPC associated with this kube cluster
	vpcID := detectVPC(svc)

	if vpcID == nil {
		fmt.Printf("VPC: not found")
		return
	}
	fmt.Print("delete VPC: " + *vpcID)
	deleteVPCRetry(svc, vpcID, 0)
	fmt.Println()
}

func deleteVPCRetry(svc *ec2.EC2, vpcID *string, retryCount int64) {
	params := &ec2.DeleteVpcInput{
		VpcId: vpcID,
	}
	_, err := svc.DeleteVpc(params)

	if awsErr, ok := err.(awserr.Error); ok {
		if awsErr.Code() == "DependencyViolation" {
			fmt.Print(".")
			retryCount++
			if retryCount > 60 {
				fmt.Println("retry limit reached for vpc deletion.")
				return
			}
			time.Sleep(time.Second * 5)
			deleteVPCRetry(svc, vpcID, retryCount)
		}
	}
}

func checkRole(roleName string) (arn *string) {
	svc := iam.New(session.New())
	params := &iam.ListRolesInput{}
	pageNum := 0
	foundRole := false
	svc.ListRolesPages(params, func(page *iam.ListRolesOutput, lastpage bool) bool {
		pageNum++
		for i := 0; i < len(page.Roles); i++ {
			if *page.Roles[i].RoleName == roleName {
				arn = page.Roles[i].Arn
				foundRole = true

			}
		}
		return lastpage || foundRole
	})
	return arn
}

func checkPolicy(shortname string) (arn *string) {
	svc := iam.New(session.New())

	done := false
	lookingForName := "k8s-" + shortname + "-" + viper.GetString("cluster-name")

	params := &iam.ListPoliciesInput{
		//MaxItems: aws.Int64(5),
		//PathPrefix:   aws.String("policyPathType"),
		Scope: aws.String("Local"),
	}
	pageNum := 0
	svc.ListPoliciesPages(params, func(page *iam.ListPoliciesOutput, lastpage bool) bool {
		pageNum++
		for i := 0; i < len(page.Policies); i++ {
			if *page.Policies[i].PolicyName == lookingForName {
				arn = page.Policies[i].Arn
				done = true
				return true
			}
		}
		return lastpage
	})
	return arn
}

func getELBDNSName(elbsvc *elb.ELB) (elbDNSName *string) {
	params := &elb.DescribeLoadBalancersInput{
		PageSize: aws.Int64(1),
		LoadBalancerNames: []*string{
			aws.String(viper.GetString("elb-name")),
		},
	}
	resp, err := elbsvc.DescribeLoadBalancers(params)

	if err != nil {
		//somethingwrong
		return nil
	}

	return resp.LoadBalancerDescriptions[0].DNSName
}

func deleteELB(elbsvc *elb.ELB, name string) bool {
	params := &elb.DeleteLoadBalancerInput{
		LoadBalancerName: aws.String(name),
	}

	_, err := elbsvc.DeleteLoadBalancer(params)
	if err != nil {
		fmt.Println("Error deleting load balancer.")
		fmt.Println(err)
	}

	fmt.Println("deleted ELB: " + name)
	return true
}

func createPolicy(policyTemplateFile string, shortname string) (arn *string) {
	templateValues := policyConf{
		viper.GetString("s3-ca-storage-bucket"),
		viper.GetString("cluster-name"),
	}
	masterTemplateText := generatePolicyFromTemplate(policyTemplateFile, templateValues)

	svc := iam.New(session.New())

	params := &iam.CreatePolicyInput{
		PolicyDocument: aws.String(masterTemplateText),
		PolicyName:     aws.String("k8s-" + shortname + "-" + viper.GetString("cluster-name")),
		Description:    aws.String("Kubernetes " + shortname + " Instance Policy" + viper.GetString("cluster-name")),
		//Path:           aws.String("/"),
	}
	resp, err := svc.CreatePolicy(params)

	if err != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		if err.(awserr.Error).Code() == "EntityAlreadyExists" {
			// Get error details
			fmt.Println("Policy exists, continue.")
			// TODO policyArn =
			// TODO: return policy ARN?
			return nil
		} else {
			fmt.Println(err.Error())
			os.Exit(1)
		}
	}

	return resp.Policy.Arn
}

func createRole(policyArn *string, roleName string) (instanceRoleArn *string) {
	svc := iam.New(session.New())
	assumeRoleBuf, err := ioutil.ReadFile(path.Join(viper.GetString("template-path"), "assume-role-policy-document.json"))
	assumeRole := string(assumeRoleBuf)

	params := &iam.CreateRoleInput{
		AssumeRolePolicyDocument: aws.String(assumeRole),
		RoleName:                 aws.String(roleName),
		//Path:                     aws.String("pathType"),
	}
	_, errRole := svc.CreateRole(params)

	if errRole != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(errRole.Error())
		os.Exit(1)
	}

	params2 := &iam.AttachRolePolicyInput{
		PolicyArn: policyArn, // Required
		RoleName:  aws.String(roleName),
	}
	_, err2 := svc.AttachRolePolicy(params2)

	if err2 != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(err2.Error())
		os.Exit(1)
	}

	params3 := &iam.CreateInstanceProfileInput{
		InstanceProfileName: aws.String(roleName), // Required
		//Path:                aws.String("pathType"),
	}
	resp3, err3 := svc.CreateInstanceProfile(params3)

	if err3 != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(err3.Error())
		os.Exit(1)
	}

	iArn := resp3.InstanceProfile.Arn

	params4 := &iam.AddRoleToInstanceProfileInput{
		InstanceProfileName: aws.String(roleName), // Required
		RoleName:            aws.String(roleName), // Required
	}
	_, err4 := svc.AddRoleToInstanceProfile(params4)

	if err4 != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(err.Error())
		os.Exit(1)
	}

	return iArn
}

func setupSecurityGroupsAuth(svc *ec2.EC2, masterSecGroupID *string, minionSecGroupID *string, ELBSecurityGroupID *string) {
	// Setup Master to Master Etcd
	paramsMMEtcd := &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: masterSecGroupID,
		IpPermissions: []*ec2.IpPermission{
			{ // Required
				FromPort:   aws.Int64(0),
				IpProtocol: aws.String("TCP"),
				ToPort:     aws.Int64(65535),
				UserIdGroupPairs: []*ec2.UserIdGroupPair{
					{ // Required
						GroupId: masterSecGroupID,
					},
				},
			},
		},
	}
	_, errMMEtcd := svc.AuthorizeSecurityGroupIngress(paramsMMEtcd)

	if errMMEtcd != nil {
		fmt.Println(errMMEtcd.Error())
		fmt.Println("Could not authorize security group for Master to Master Etcd")
		os.Exit(1)
	}

	// Setup Master SSH
	paramsMasterSSH := &ec2.AuthorizeSecurityGroupIngressInput{
		CidrIp:     aws.String("0.0.0.0/0"),
		FromPort:   aws.Int64(22),
		GroupId:    masterSecGroupID,
		IpProtocol: aws.String("TCP"),
		ToPort:     aws.Int64(22),
	}
	_, errMasterSSH := svc.AuthorizeSecurityGroupIngress(paramsMasterSSH)
	if errMasterSSH != nil {
		fmt.Println("Could not authorize security group for Master SSH")
		os.Exit(1)
	}

	// Setup Minion SSH
	paramsMinionSSH := &ec2.AuthorizeSecurityGroupIngressInput{
		CidrIp:     aws.String("0.0.0.0/0"),
		FromPort:   aws.Int64(22),
		GroupId:    minionSecGroupID,
		IpProtocol: aws.String("TCP"),
		ToPort:     aws.Int64(22),
	}
	_, errMinionSSH := svc.AuthorizeSecurityGroupIngress(paramsMinionSSH)
	if errMinionSSH != nil {
		fmt.Println("Could not authorize security group for Minion SSH")
		os.Exit(1)
	}

	// Setup Minion to Master port 6443 (API access)
	params1 := &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: masterSecGroupID,
		IpPermissions: []*ec2.IpPermission{
			{ // Required
				FromPort:   aws.Int64(6443),
				IpProtocol: aws.String("TCP"),
				ToPort:     aws.Int64(6443),
				UserIdGroupPairs: []*ec2.UserIdGroupPair{
					{ // Required
						GroupId: minionSecGroupID,
					},
				},
			},
		},
	}
	_, err1 := svc.AuthorizeSecurityGroupIngress(params1)

	if err1 != nil {
		fmt.Println(err1.Error())
		fmt.Println("Could not authorize security group for Minion to Master")
		os.Exit(1)
	}

	// Setup Minion to Minion
	params5 := &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: minionSecGroupID,
		IpPermissions: []*ec2.IpPermission{
			{ // Required
				FromPort:   aws.Int64(0),
				IpProtocol: aws.String("TCP"),
				ToPort:     aws.Int64(65535),
				UserIdGroupPairs: []*ec2.UserIdGroupPair{
					{ // Required
						GroupId: minionSecGroupID,
					},
				},
			},
		},
	}
	_, err5 := svc.AuthorizeSecurityGroupIngress(params5)

	if err5 != nil {
		fmt.Println(err5.Error())
		fmt.Println("Could not authorize security group for Minion to Minion")
		os.Exit(1)
	}

	params6 := &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: minionSecGroupID,
		IpPermissions: []*ec2.IpPermission{
			{ // Required
				FromPort:   aws.Int64(0),
				IpProtocol: aws.String("UDP"),
				ToPort:     aws.Int64(65535),
				UserIdGroupPairs: []*ec2.UserIdGroupPair{
					{ // Required
						GroupId: minionSecGroupID,
					},
				},
			},
		},
	}
	_, err6 := svc.AuthorizeSecurityGroupIngress(params6)

	if err6 != nil {
		fmt.Println(err6.Error())
		fmt.Println("Could not authorize security group for Minion to Minion UDP")
		os.Exit(1)
	}

	// Setup Master to Minion
	params2 := &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: minionSecGroupID,
		IpPermissions: []*ec2.IpPermission{
			{ // Required
				FromPort:   aws.Int64(0),
				IpProtocol: aws.String("TCP"),
				ToPort:     aws.Int64(65535),
				UserIdGroupPairs: []*ec2.UserIdGroupPair{
					{ // Required
						GroupId: masterSecGroupID,
					},
				},
			},
		},
	}
	_, err2 := svc.AuthorizeSecurityGroupIngress(params2)

	if err2 != nil {
		fmt.Println(err2.Error())
		fmt.Println("Could not authorize security group for Master to Minion")
		os.Exit(1)
	}

	// Setup ELB to Master
	params3 := &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: masterSecGroupID,
		IpPermissions: []*ec2.IpPermission{
			{ // Required
				FromPort:   aws.Int64(6443),
				IpProtocol: aws.String("TCP"),
				ToPort:     aws.Int64(6443),
				UserIdGroupPairs: []*ec2.UserIdGroupPair{
					{ // Required
						GroupId: ELBSecurityGroupID,
					},
				},
			},
		},
	}
	_, err3 := svc.AuthorizeSecurityGroupIngress(params3)

	if err3 != nil {
		fmt.Println(err3.Error())
		fmt.Println("Could not authorize security group for Master to Minion")
		os.Exit(1)
	}

	// Setup ELB Public 443
	params4 := &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: ELBSecurityGroupID,
		IpPermissions: []*ec2.IpPermission{
			{ // Required
				FromPort:   aws.Int64(443),
				IpProtocol: aws.String("TCP"),
				ToPort:     aws.Int64(443),
				IpRanges: []*ec2.IpRange{
					{
						CidrIp: aws.String("0.0.0.0/0"),
					},
				},
			},
		},
	}
	_, err4 := svc.AuthorizeSecurityGroupIngress(params4)

	if err4 != nil {
		fmt.Println("Could not authorize security group ELB access 443")
		fmt.Println(err4)
		os.Exit(1)
	}

}

func createSecurityGroup(svc *ec2.EC2, kindOf string, vpcID *string) (securityGroupID *string) {
	groupName := "kubernetes-" + kindOf + "-" + viper.GetString("cluster-name")
	params := &ec2.CreateSecurityGroupInput{
		Description: aws.String(groupName), // Required
		GroupName:   aws.String(groupName),
		VpcId:       vpcID,
	}
	resp, err := svc.CreateSecurityGroup(params)

	if err != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(err.Error())
		os.Exit(1)
		return
	}

	securityGroupID = resp.GroupId

	// Tag with the necessary tags
	tagIt(svc, securityGroupID)
	tagFor(svc, securityGroupID, kindOf)

	return securityGroupID
}

func createELB(svc *ec2.EC2, elbsvc *elb.ELB, vpcID *string) (elbDNSName *string) {

	// Create or lookup elb security group
	securityGroupID := getSecurityGroup(svc, "ELB")

	if securityGroupID == nil {
		fmt.Printf("Creating security group for Kubernetes Master ELB.")
		fmt.Println("could not find security group for kubernetes master ELB.")
		os.Exit(1)
		//securityGroupID = createSecurityGroup(svc, "ELB", vpcID)
	}

	// Create ELB
	params := &elb.CreateLoadBalancerInput{
		Listeners: []*elb.Listener{
			{
				InstancePort:     aws.Int64(6443),
				LoadBalancerPort: aws.Int64(443),
				Protocol:         aws.String("TCP"),
				InstanceProtocol: aws.String("TCP"),
			},
		},
		LoadBalancerName: aws.String(viper.GetString("elb-name")),
		Scheme:           aws.String("internet-facing"),
		SecurityGroups: []*string{
			securityGroupID,
		},
		Subnets: []*string{
			getSubnets(svc), // Hack, only returns one subnet
		},
		Tags: []*elb.Tag{
			{
				Key:   aws.String("KubernetesCluster"),
				Value: aws.String(viper.GetString("cluster-name")),
			},
		},
	}
	resp, err := elbsvc.CreateLoadBalancer(params)

	if err != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(err.Error())
		os.Exit(1)
		return
	}

	// Configure Health Check
	paramsHC := &elb.ConfigureHealthCheckInput{
		LoadBalancerName: aws.String(viper.GetString("elb-name")),
		HealthCheck: &elb.HealthCheck{
			HealthyThreshold:   aws.Int64(2),
			Interval:           aws.Int64(5),
			Target:             aws.String("TCP:6443"),
			Timeout:            aws.Int64(3),
			UnhealthyThreshold: aws.Int64(2),
		},
	}

	_, errHC := elbsvc.ConfigureHealthCheck(paramsHC)

	if errHC != nil {
		fmt.Println("Error configuring health check for Master ELB.  Continuing")
		fmt.Println(errHC)
	}

	return resp.DNSName

}

func stripSecGroup(svc *ec2.EC2, secGroupID *string) {
	// First detangle the group from other groups.
	paramsDesc := &ec2.DescribeSecurityGroupsInput{
		GroupIds: []*string{secGroupID},
	}

	respDesc, errDesc := svc.DescribeSecurityGroups(paramsDesc)
	if errDesc != nil {
		fmt.Println("error describing security groups")
		fmt.Println(errDesc)
	}

	paramsDeleteRules := &ec2.RevokeSecurityGroupIngressInput{
		GroupId:       secGroupID,
		IpPermissions: respDesc.SecurityGroups[0].IpPermissions,
	}

	_, err := svc.RevokeSecurityGroupIngress(paramsDeleteRules)
	if err != nil {
		fmt.Println("error removing rules from security group")
		fmt.Println(err)
		return
	}
	fmt.Println("removed rules from: " + *secGroupID)

}

func deleteSecGroup(svc *ec2.EC2, secGroupID *string, retryCount int64) bool {
	params := &ec2.DeleteSecurityGroupInput{
		GroupId: secGroupID,
	}
	_, err := svc.DeleteSecurityGroup(params)
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "DependencyViolation" {
				fmt.Print(".")
				retryCount++
				if retryCount > 60 {
					fmt.Println("retry limit reached for security group deletion.")
					return false
				}
				time.Sleep(time.Second * 5)
				deleteSecGroup(svc, secGroupID, retryCount)
			}
		} else {
			fmt.Println(err.Error())
		}
		return false
	}

	return true
}

func deleteIGW(svc *ec2.EC2) bool {
	params := &ec2.DescribeInternetGatewaysInput{
		Filters: []*ec2.Filter{
			{
				Name: aws.String("tag:KubernetesCluster"),
				Values: []*string{
					aws.String(viper.GetString("cluster-name")),
				},
			},
		},
	}

	resp, err := svc.DescribeInternetGateways(params)
	if err != nil || len(resp.InternetGateways) == 0 {
		fmt.Println("IGW: not found")
		if err != nil {
			fmt.Println(err)
		}
		return false
	}

	fmt.Print("delete IGW: " + *resp.InternetGateways[0].InternetGatewayId)

	paramsDetach := &ec2.DetachInternetGatewayInput{
		InternetGatewayId: resp.InternetGateways[0].InternetGatewayId,
		VpcId:             resp.InternetGateways[0].Attachments[0].VpcId,
	}

	_, errDetach := svc.DetachInternetGateway(paramsDetach)

	if errDetach != nil {
		fmt.Println("error detaching IGW from vpc")
		fmt.Println(errDetach)
		return false
	}

	deleteIGWRetry(svc, resp.InternetGateways[0].InternetGatewayId, 0)
	fmt.Println()
	return true
}

func deleteSSHKey(svc *ec2.EC2) bool {
	deleteParams := &ec2.DeleteKeyPairInput{
		KeyName: aws.String(viper.GetString("ssh-key-name")),
	}
	_, err := svc.DeleteKeyPair(deleteParams)
	if err != nil {
		fmt.Println("Error deleting keypair")
		fmt.Println(err)
		return false
	} else {
		fmt.Println("Deleted keypair: " + viper.GetString("ssh-key-name"))
		return true
	}
}

func deleteIGWRetry(svc *ec2.EC2, IGWID *string, retryCount int64) bool {
	paramsDelete := &ec2.DeleteInternetGatewayInput{
		InternetGatewayId: IGWID,
	}

	_, errDelete := svc.DeleteInternetGateway(paramsDelete)

	if errDelete != nil {
		if awsErr, ok := errDelete.(awserr.Error); ok {
			if awsErr.Code() == "DependencyViolation" {
				fmt.Print(".")
				retryCount++
				if retryCount > 60 {
					fmt.Println("retry limit reached for IGW deletion.")
					return false
				}
				time.Sleep(time.Second * 5)
				deleteIGWRetry(svc, IGWID, retryCount)
			}
		} else {
			fmt.Println(errDelete.Error())
		}
	}
	return true
}

func deleteRouteTable(svc *ec2.EC2) bool {
	params := &ec2.DescribeRouteTablesInput{
		Filters: []*ec2.Filter{
			{
				Name: aws.String("tag:KubernetesCluster"),
				Values: []*string{
					aws.String(viper.GetString("cluster-name")),
				},
			},
		},
	}

	resp, err := svc.DescribeRouteTables(params)

	if err != nil || len(resp.RouteTables) == 0 {
		fmt.Println("Route Table: not found")
		if err != nil {
			fmt.Println(err)
		}
		return false
	}
	fmt.Print("delete Route Table: " + *resp.RouteTables[0].RouteTableId)
	deleteRouteTableRetry(svc, resp.RouteTables[0].RouteTableId, 0)
	fmt.Println()
	return true
}

func deleteRouteTableRetry(svc *ec2.EC2, routeTableID *string, retryCount int64) {
	paramsDelete := &ec2.DeleteRouteTableInput{
		RouteTableId: routeTableID,
	}

	_, errDelete := svc.DeleteRouteTable(paramsDelete)

	if errDelete != nil {
		if awsErr, ok := errDelete.(awserr.Error); ok {
			if awsErr.Code() == "DependencyViolation" {
				fmt.Print(".")
				retryCount++
				if retryCount > 60 {
					fmt.Println("retry limit reached for dhcpOptions deletion.")
					return
				}
				time.Sleep(time.Second * 5)
				deleteRouteTableRetry(svc, routeTableID, retryCount)
			}
		} else {
			fmt.Println(errDelete)
		}
	}
}

func deleteDhcpOptionSet(svc *ec2.EC2) bool {
	params := &ec2.DescribeDhcpOptionsInput{
		Filters: []*ec2.Filter{
			{
				Name: aws.String("tag:KubernetesCluster"),
				Values: []*string{
					aws.String(viper.GetString("cluster-name")),
				},
			},
		},
	}

	resp, err := svc.DescribeDhcpOptions(params)

	if err != nil || len(resp.DhcpOptions) == 0 {
		fmt.Println("error describing dhcp option sets")
		fmt.Println(err)
		return false
	}
	fmt.Print("delete DHCP options set: " + *resp.DhcpOptions[0].DhcpOptionsId)
	deleteDhcpOptionsRetry(svc, resp.DhcpOptions[0].DhcpOptionsId, 0)
	fmt.Println()
	return true
}

func deleteDhcpOptionsRetry(svc *ec2.EC2, dhcpOptionsID *string, retryCount int64) {
	paramsDelete := &ec2.DeleteDhcpOptionsInput{
		DhcpOptionsId: dhcpOptionsID,
	}

	_, respErr := svc.DeleteDhcpOptions(paramsDelete)

	if respErr != nil {
		if awsErr, ok := respErr.(awserr.Error); ok {
			if awsErr.Code() == "DependencyViolation" {
				fmt.Print(".")
				retryCount++
				if retryCount > 60 {
					fmt.Println("retry limit reached for dhcpOptions deletion.")
					return
				}
				time.Sleep(time.Second * 5)
				deleteIGWRetry(svc, dhcpOptionsID, retryCount)
			}
		} else {
			fmt.Println(respErr.Error())
		}
	}
}

func deleteSubnet(svc *ec2.EC2, subnetID *string, retryCount int64) bool {
	params := &ec2.DeleteSubnetInput{
		SubnetId: subnetID,
	}

	_, err := svc.DeleteSubnet(params)

	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "DependencyViolation" {
				fmt.Print(".")
				retryCount++
				if retryCount > 60 {
					fmt.Println("retry limit reached for subnet deletion.")
					return false
				}
				time.Sleep(time.Second * 5)
				deleteSubnet(svc, subnetID, retryCount)
			}
		} else {
			fmt.Println(err.Error())
		}
	}

	return true
}

func deleteSubnets(svc *ec2.EC2) bool {
	params := &ec2.DescribeSubnetsInput{
		Filters: []*ec2.Filter{
			{
				Name: aws.String("tag:KubernetesCluster"),
				Values: []*string{
					aws.String(viper.GetString("cluster-name")),
				},
			},
		},
	}

	resp, err := svc.DescribeSubnets(params)

	if err != nil {
		fmt.Println("error describing subnets")
		fmt.Println(err)
		return false
	}

	allSuccess := true
	for i := 0; i < len(resp.Subnets); i++ {
		fmt.Println("delete subnet: " + *resp.Subnets[i].SubnetId)
		if deleteSubnet(svc, resp.Subnets[i].SubnetId, 0) == false {
			allSuccess = false
		}
	}
	fmt.Println()
	return allSuccess
}

func waitInstanceTerminated(svc *ec2.EC2, instanceID *string) bool {
	// Use a waiter function to wait until the instances are stopped.
	describeInstancesInput := &ec2.DescribeInstancesInput{
		InstanceIds: []*string{instanceID},
	}
	if err := svc.WaitUntilInstanceTerminated(describeInstancesInput); err !=
		nil {
		fmt.Println(err)
		return (false)
	}
	fmt.Println("Instance is terminated.")
	return true
}

func deleteKubeELBs(svc *elb.ELB) bool {
	params := &elb.DescribeLoadBalancersInput{}
	pageNum := 0

	svc.DescribeLoadBalancersPages(params, func(page *elb.DescribeLoadBalancersOutput, lastpage bool) bool {
		pageNum++
		for i := 0; i < len(page.LoadBalancerDescriptions); i++ {
			thisName := page.LoadBalancerDescriptions[i].LoadBalancerName
			getTagsParams := &elb.DescribeTagsInput{
				LoadBalancerNames: []*string{thisName},
			}
			tagResp, tagErr := svc.DescribeTags(getTagsParams)
			if tagErr != nil {
				fmt.Println("Error describing tags for ELB")
				fmt.Println(tagErr)
			}
			for k := range tagResp.TagDescriptions[0].Tags {
				if *tagResp.TagDescriptions[0].Tags[k].Key == "KubernetesCluster" && *tagResp.TagDescriptions[0].Tags[k].Value == viper.GetString("cluster-name") {
					deleteELB(svc, *tagResp.TagDescriptions[0].LoadBalancerName)
				}
			}
		}
		return lastpage
	})
	return true
}

func waitForKubeOperational() {
	done := false
	fmt.Println("waiting for kubectl get nodes to exit successfully.")
	for done == false {
		_, errExec := exec.Command("kubectl", "get", "nodes", "--kubeconfig", viper.GetString("kube-config-home")).CombinedOutput()
		if errExec != nil {
			//fmt.Println(errExec)
			//fmt.Println(string(out))
			fmt.Printf(".")
			time.Sleep(time.Second * 5)
		} else {
			done = true
			fmt.Println("Kubernetes api server responded")
		}
	}
}

func loadDNSAddon() {
	targetFileName := "kube-dns-" + viper.GetString("cluster-name") + ".yaml"
	exec.Command("kubectl", "create", "namespace", "kube-system", "--kubeconfig", viper.GetString("kube-config-home")).CombinedOutput()
	exec.Command("kubectl", "create", "-f", targetFileName, "--kubeconfig", viper.GetString("kube-config-home")).CombinedOutput()
}

func deletePoliciesRoles() {
	iamSvc := iam.New(session.New())

	// First detach the role from all the Instance Policies
	listInstanceProfilesForMaster := &iam.ListInstanceProfilesForRoleInput{
		RoleName: aws.String("k8s-master" + viper.GetString("cluster-name")),
	}

	listInstanceProfilesForMinion := &iam.ListInstanceProfilesForRoleInput{
		RoleName: aws.String("k8s-minion" + viper.GetString("cluster-name")),
	}

	respMasterProfile, _ := iamSvc.ListInstanceProfilesForRole(listInstanceProfilesForMaster)
	respMinionProfile, _ := iamSvc.ListInstanceProfilesForRole(listInstanceProfilesForMinion)

	for i := 0; i < len(respMasterProfile.InstanceProfiles); i++ {
		detachInstanceProfileMaster := &iam.RemoveRoleFromInstanceProfileInput{
			InstanceProfileName: respMasterProfile.InstanceProfiles[i].InstanceProfileName,
			RoleName:            aws.String("k8s-master" + viper.GetString("cluster-name")),
		}
		_, errRemoveMaster := iamSvc.RemoveRoleFromInstanceProfile(detachInstanceProfileMaster)
		detachInstanceProfileMinion := &iam.RemoveRoleFromInstanceProfileInput{
			InstanceProfileName: respMinionProfile.InstanceProfiles[i].InstanceProfileName,
			RoleName:            aws.String("k8s-minion" + viper.GetString("cluster-name")),
		}
		_, errRemoveMinion := iamSvc.RemoveRoleFromInstanceProfile(detachInstanceProfileMinion)

		if errRemoveMaster != nil {
			fmt.Println("Error removing role from Master instance profile")
			fmt.Println(errRemoveMaster)
		}
		if errRemoveMinion != nil {
			fmt.Println("Error removing role from Minion instance profile")
			fmt.Println(errRemoveMinion)
		}

	}

	// Detach all policies from roles

	delRolePolicyMasterInput := &iam.DetachRolePolicyInput{
		PolicyArn: checkPolicy("master"),
		RoleName:  aws.String("k8s-master" + viper.GetString("cluster-name")),
	}

	delRolePolicyMinionInput := &iam.DetachRolePolicyInput{
		PolicyArn: checkPolicy("minion"),
		RoleName:  aws.String("k8s-minion" + viper.GetString("cluster-name")),
	}

	_, errDeleteRolePolicyMaster := iamSvc.DetachRolePolicy(delRolePolicyMasterInput)
	_, errDeleteRolePolicyMinion := iamSvc.DetachRolePolicy(delRolePolicyMinionInput)

	if errDeleteRolePolicyMaster != nil {
		fmt.Println("Error detaching policy from Master role.")
		fmt.Println(errDeleteRolePolicyMaster)
	}
	if errDeleteRolePolicyMinion != nil {
		fmt.Println("Error detaching policy from Minion role.")
		fmt.Println(errDeleteRolePolicyMinion)
	}

	// Delete Roles
	delRoleMasterInput := &iam.DeleteRoleInput{
		RoleName: aws.String("k8s-master" + viper.GetString("cluster-name")),
	}
	delRoleMinionInput := &iam.DeleteRoleInput{
		RoleName: aws.String("k8s-minion" + viper.GetString("cluster-name")),
	}

	_, errMaster := iamSvc.DeleteRole(delRoleMasterInput)
	_, errMinion := iamSvc.DeleteRole(delRoleMinionInput)

	if errMaster != nil {
		fmt.Println("Error during deletion of Master Role:")
		fmt.Println(errMaster)
	}
	if errMinion != nil {
		fmt.Println("Error during deletion of Minion Role:")
		fmt.Println(errMinion)
	}

	// Delete Policies
	delPolicyMasterInput := &iam.DeletePolicyInput{
		PolicyArn: checkPolicy("master"),
	}

	_, delPolicyMasterErr := iamSvc.DeletePolicy(delPolicyMasterInput)

	if delPolicyMasterErr != nil {
		fmt.Println("Error deleting policy for master.")
		fmt.Println(delPolicyMasterErr)
	}

	delPolicyMinionInput := &iam.DeletePolicyInput{
		PolicyArn: checkPolicy("minion"),
	}

	_, delPolicyMinionErr := iamSvc.DeletePolicy(delPolicyMinionInput)

	if delPolicyMinionErr != nil {
		fmt.Println("Error deleting policy for minion.")
		fmt.Println(delPolicyMinionErr)
	}

	// Delete Instance Profiles
	delInstProfileMaster := &iam.DeleteInstanceProfileInput{
		InstanceProfileName: aws.String("k8s-master" + viper.GetString("cluster-name")),
	}

	_, delInstProfileMasterErr := iamSvc.DeleteInstanceProfile(delInstProfileMaster)

	if delInstProfileMasterErr != nil {
		fmt.Println("Error deleting instance profile for master.")
		fmt.Println(delInstProfileMasterErr)
	}

	delInstProfileMinion := &iam.DeleteInstanceProfileInput{
		InstanceProfileName: aws.String("k8s-minion" + viper.GetString("cluster-name")),
	}

	_, delInstProfileMinionErr := iamSvc.DeleteInstanceProfile(delInstProfileMinion)

	if delInstProfileMinionErr != nil {
		fmt.Println("Error deleting instance profile for minion.")
		fmt.Println(delInstProfileMinionErr)
	}
}

func createSSHKey(svc *ec2.EC2) bool {
	descParams := &ec2.DescribeKeyPairsInput{
		KeyNames: []*string{aws.String(viper.GetString("ssh-key-name"))},
	}

	respDesc, errDesc := svc.DescribeKeyPairs(descParams)
	if errDesc != nil {
		if awsErr, ok := errDesc.(awserr.Error); ok {
			if awsErr.Code() == "InvalidKeyPair.NotFound" {
				// simply continue, we will create the key.
			} else {
				handleError(errDesc, "Error describing key pairs")
			}
		} else {
			handleError(errDesc, "Error describing key pairs")
		}
	}

	if respDesc.KeyPairs == nil {
		createParams := &ec2.CreateKeyPairInput{
			KeyName: aws.String(viper.GetString("ssh-key-name")),
		}

		respCreate, errCreate := svc.CreateKeyPair(createParams)
		handleError(errCreate, "Error creating ssh key pair")

		keyFileName := path.Join(os.Getenv("HOME"), ".launch", viper.GetString("cluster-name"), "id_rsa")
		fmt.Println("Create SSH keypair: " + viper.GetString("ssh-key-name") + " location " + keyFileName)

		keyMaterial := []byte(*respCreate.KeyMaterial)
		handleError(ioutil.WriteFile(keyFileName, keyMaterial, 0600), "error writing to "+keyFileName)

		// Nice to have but not necessary at all, public key generation.
		//block, _ := pem.Decode(keyMaterial)
		//cert, err := x509.ParseCertificate(block.Bytes)
		//handleError(err, "could not parse private key")
		//rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)
		//handleError(ioutil.WriteFile(string(rsaPublicKey.E), append([]byte(".pub"), keyFileName...), 0400), "could not write public key")
		//fmt.Printf("created rsa keypair %s in %s", viper.GetString("ssh-key-name"), keyFileName)
	}
	return true
}

func handleError(err error, message string) {
	if err != nil {
		os.Stderr.WriteString(message)
		fmt.Println(os.Stderr, err)
		os.Stderr.WriteString("Exiting.")
		os.Exit(1)
	}
	return
}

func newUUID() (string, error) {
	uuid := make([]byte, 16)
	n, err := io.ReadFull(rand.Reader, uuid)
	if n != len(uuid) || err != nil {
		return "", err
	}
	// variant bits; see section 4.1.1
	uuid[8] = uuid[8]&^0xc0 | 0x80
	// version 4 (pseudo-random); see section 4.1.3
	uuid[6] = uuid[6]&^0xf0 | 0x40
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]), nil
}

func main() {

	// Flags
	var action = flag.String("action", "", "Action can be: init, launch-minion")
	var confFile = flag.String("conf", "", "Path to config file")
	flag.Parse()
	switch *action {
	case "init":
	case "launch-minion":
	case "delete":
	case "generate-kube-config":
	default:
		fmt.Println("Usage:  up -action=<ACTION>  Please specify an action: init, launch-minion, delete.")
		os.Exit(1)
	}

	defaultClusterName := "launch-default"
	defaultConfigFilePath := path.Join(os.Getenv("HOME"), ".launch", defaultClusterName)
	defaultViperConfig := path.Join(defaultConfigFilePath, "config", "config.toml")

	if _, errDefaultExists := os.Stat(defaultViperConfig); os.IsNotExist(errDefaultExists) {
		// Default config does not exist.  Create it.
		errorConfigDefault := RestoreAsset(defaultConfigFilePath, "config/config.toml")
		handleError(errorConfigDefault, "Error creating default config.")
	}

	viper.SetConfigName("config")

	if *confFile == "" {
		viper.AddConfigPath(path.Join(defaultConfigFilePath, "config"))
	} else {
		viper.AddConfigPath(*confFile)
	}

	viper.SetEnvPrefix("BB")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}

	viper.SetDefault("elb-name", "k8s-master-"+viper.GetString("cluster-name"))
	viper.SetDefault("ami-update-url", "https://blackbird.cx/amis/latest/")
	// Set default path to kube config file and certificate store
	//fmt.Println("kubeconfighome" + viper.GetString("kube-config-home"))
	latestAMI := getLatestAmi()
	if latestAMI != "" {
		viper.SetDefault("ami", latestAMI)
	}

	viper.SetDefault("configuration-files-path", path.Join(os.Getenv("HOME"), ".launch", viper.GetString("cluster-name")))
	viper.SetDefault("kube-config-home", path.Join(viper.GetString("configuration-files-path"), "kubeconfig"))
	viper.SetDefault("template-path", path.Join(viper.GetString("configuration-files-path"), "templates"))
	viper.SetDefault("certificate-path", path.Join(viper.GetString("configuration-files-path"), "k8s_certs"))
	viper.SetDefault("ssh-key-name", "launch-"+viper.GetString("cluster-name"))
	viper.SetDefault("minion-instance-type", "t2.micro")
	viper.SetDefault("master-instance-type", "t2.micro")
	viper.SetDefault("minion-root-volume-size", 50)

	// Initial s3 bucket name generation
	if !viper.IsSet("s3-ca-storage-bucket") {
		globalConfig := path.Join(os.Getenv("HOME"), ".launch", "s3-ca-storage-bucketname.conf")

		if _, errDefaultExists := os.Stat(globalConfig); os.IsNotExist(errDefaultExists) {
			// global config does not exist yet
			// generate a random bucket name
			genUUID, _ := newUUID()
			s3Name := "launch-certs" + genUUID
			// write to global config
			ioutil.WriteFile(globalConfig, []byte(s3Name), 0660)
			viper.Set("s3-ca-storage-bucket", s3Name)
		} else {
			// Read global config
			s3Bucket, _ := ioutil.ReadFile(globalConfig)
			viper.Set("s3-ca-storage-bucket", string(s3Bucket))
		}
	}

	// Unpack Asset helpers into the configured paths
	errorCerts := RestoreAssets(viper.GetString("configuration-files-path"), "k8s_certs")
	if errorCerts != nil {
		fmt.Println("Error writing template files")
		fmt.Println(errorCerts)
		os.Exit(1)
	}
	errorTemplates := RestoreAssets(viper.GetString("configuration-files-path"), "templates")
	if errorTemplates != nil {
		fmt.Println("Error writing template files")
		fmt.Println(errorTemplates)
		os.Exit(1)
	}

	svc := ec2.New(session.New(), &aws.Config{Region: aws.String(viper.GetString("region"))})
	elbSvc := elb.New(session.New(), &aws.Config{Region: aws.String(viper.GetString("region"))})

	if *action == "delete" {
		/* fmt.Printf("Tearing down K8S cluster for tag: %s\n", viper.GetString("cluster-name"))
		fmt.Println("Press 'Enter' to continue... CTRL-C to abort.")
		bufio.NewReader(os.Stdin).ReadBytes('\n') */

		// start with instances (tagged)
		deleteInstances(svc)

		// then elbs (tagged)
		deleteELB(elbSvc, viper.GetString("elb-name"))

		deleteKubeELBs(elbSvc)

		deletePoliciesRoles()

		// Remove references from security groups so they can be deleted
		elbSecGroupID := getSecurityGroup(svc, "ELB")
		masterSecGroupID := getSecurityGroup(svc, "Master")
		minionSecGroupID := getSecurityGroup(svc, "Minion")

		stripSecGroup(svc, elbSecGroupID)
		stripSecGroup(svc, masterSecGroupID)
		stripSecGroup(svc, minionSecGroupID)

		// Security Groups (tagged)
		fmt.Print("deleting security groups ")
		deleteSecGroup(svc, elbSecGroupID, 0)
		deleteSecGroup(svc, masterSecGroupID, 0)
		deleteSecGroup(svc, minionSecGroupID, 0)
		fmt.Println()

		deleteSecGroupsExtra(svc)

		// SSH Key
		deleteSSHKey(svc)

		// IGW (tagged)
		deleteIGW(svc)

		// Dhcp Option set (tagged) VPCs can use the same options set.
		deleteDhcpOptionSet(svc)

		// All clear for Subnet delete (tagged)
		deleteSubnets(svc)

		// teardown VPC (tagged)
		deleteVPC(svc)

		// Route Table (tagged)
		deleteRouteTable(svc)

		fmt.Println("Kubernetes deletion sweep complete.")
		os.Exit(0)
	}

	if *action == "generate-kube-config" {
		elbDNSName := getELBDNSName(elbSvc)
		// Drop in kube config for laptop user
		kubeConfigValues := userKubeConfig{
			"https://" + *elbDNSName,
			viper.GetString("certificate-path") + "/ca.pem",
			viper.GetString("certificate-path") + "/admin.pem",
			viper.GetString("certificate-path") + "/admin-key.pem",
		}

		generateUserLaptopKubeConfig(kubeConfigValues)
		fmt.Println("kubeconfig generated.")
		os.Exit(0)
	}

	// Begin Create
	vpcID := detectVPC(svc)
	if vpcID == nil {
		vpcID = createVPCNetworking(svc)
	} else {
		fmt.Println("Found VPC: " + *vpcID)
	}

	templateDir := viper.GetString("template-path")

	waitForPolicy := false
	// IAM Roles for Master and Minion
	masterArn := checkPolicy("master")
	if masterArn == nil {
		masterArn = createPolicy(path.Join(templateDir, "kube-master-iam-policy.json"), "master")
		fmt.Println("Created policy: " + *masterArn)
		waitForPolicy = true
	} else {
		fmt.Println("found policy: " + *masterArn)
	}

	minionArn := checkPolicy("minion")
	if minionArn == nil {
		minionArn = createPolicy(path.Join(templateDir, "kube-minion-iam-policy.json"), "minion")
		fmt.Println("Created policy: " + *minionArn)
		waitForPolicy = true
	} else {
		fmt.Println("found policy: " + *minionArn)
	}

	masterRoleName := "k8s-master" + viper.GetString("cluster-name")
	instanceProfileArnMaster := checkRole(masterRoleName)
	if instanceProfileArnMaster == nil {
		instanceProfileArnMaster = createRole(masterArn, masterRoleName)
		fmt.Println("Created role: " + *instanceProfileArnMaster)
		waitForPolicy = true
	} else {
		fmt.Println("found role: " + *instanceProfileArnMaster)
	}

	minionRoleName := "k8s-minion" + viper.GetString("cluster-name")
	instanceProfileArnMinion := checkRole(minionRoleName)
	if instanceProfileArnMinion == nil {
		instanceProfileArnMinion = createRole(minionArn, minionRoleName)
		fmt.Println("Created role: " + *instanceProfileArnMinion)
		waitForPolicy = true
	} else {
		fmt.Println("found role: " + *instanceProfileArnMinion)
	}

	// S3 Bucket for certs
	createS3Bucket()

	if waitForPolicy {
		// TODO: instead of sleep, check for iam role to exist from ec2.
		fmt.Println("waiting for policy changes to sync")
		time.Sleep(time.Second * 60)
	}

	// Sanity check S3 permission by writing test.
	if putObjS3("preflight-check1.0", "preflight-check") == false {
		fmt.Println("Error: Unable to write to s3 bucket.  Please check permissions and try again.  This bucket name may already be taken.")
		os.Exit(1)
	}

	// Create SSH key if not exists.
	createSSHKey(svc)

	// Ensure Security groups are Created and authorized
	authorize := false
	masterSecurityGroupID := getSecurityGroup(svc, "Master")
	if masterSecurityGroupID == nil {
		masterSecurityGroupID = createSecurityGroup(svc, "Master", vpcID)
		fmt.Println("Created master security group: " + *masterSecurityGroupID)
		authorize = true
	} else {
		fmt.Println("found master security group: " + *masterSecurityGroupID)
	}
	minionSecurityGroupID := getSecurityGroup(svc, "Minion")
	if minionSecurityGroupID == nil {
		minionSecurityGroupID = createSecurityGroup(svc, "Minion", vpcID)
		fmt.Println("Created minion security group: " + *minionSecurityGroupID)
		authorize = true
	} else {
		fmt.Println("found minion security group: " + *minionSecurityGroupID)
	}
	// Create or lookup elb security group
	ELBSecurityGroupID := getSecurityGroup(svc, "ELB")
	if ELBSecurityGroupID == nil {
		ELBSecurityGroupID = createSecurityGroup(svc, "ELB", vpcID)
		fmt.Println("Created master ELB security group: " + *ELBSecurityGroupID)
		authorize = true
	} else {
		fmt.Println("found master ELB security group: " + *ELBSecurityGroupID)
	}
	if authorize == true {
		fmt.Println("authorizing security groups for cluster communication")
		setupSecurityGroupsAuth(svc, masterSecurityGroupID, minionSecurityGroupID, ELBSecurityGroupID)
	}

	// ELB for master nodes
	elbDNSName := getELBDNSName(elbSvc)
	if elbDNSName == nil {
		elbDNSName = createELB(svc, elbSvc, vpcID)
		fmt.Println("Created ELB for " + viper.GetString("elb-name") + ": " + *elbDNSName)
	} else {
		fmt.Println("found ELB DNS name: " + *elbDNSName)
	}

	// Security Groups for kube.  Lookup for launch uses Tagged with KubernetesCluster=cluster-name
	var discovery string
	if *action == "init" {
		// Discovery service token
		discovery = getEtcdDiscoveryService(viper.GetString("master-cluster-size"))
	}

	// Generate user-data for master from config values. (also used by minion)
	templateValuesMaster := templateValuesForUserData{
		viper.GetString("service-cluster-ip-range"),
		viper.GetString("cluster-dns"),
		viper.GetString("cluster-cidr"),
		viper.GetString("cluster-name"),
		*elbDNSName,
		discovery,
		viper.GetString("s3-ca-storage-bucket"),
	}

	if *action == "init" {

		masterUserData := generateUserDataFromTemplate(path.Join(viper.GetString("template-path"), "master-user-data.template"), templateValuesMaster)
		masterUserDataEncoded := base64.StdEncoding.EncodeToString([]byte(masterUserData))

		// Launch Master(s)
		times, _ := strconv.ParseInt(viper.GetString("master-cluster-size"), 10, 0)
		var mloop int64
		for mloop = 0; mloop < times; mloop++ {
			masterInstanceID := launchMaster(svc, masterUserDataEncoded, *instanceProfileArnMaster, vpcID)

			masterSSLSettings := sslConf{
				"", //un-necessary on master
				*elbDNSName,
			}

			apiPem, apiKey, ca := generateSSL(path.Join(viper.GetString("template-path"), "master-openssl.cnf.template"),
				masterSSLSettings,
				"./generate_api_keypair.sh",
				"apiserver",
			)

			// upload certs to S3
			putObjS3(viper.GetString("cluster-name")+"/"+*masterInstanceID+"-"+"apiserver.pem", apiPem)
			putObjS3(viper.GetString("cluster-name")+"/"+*masterInstanceID+"-"+"apiserver-key.pem", apiKey)
			putObjS3(viper.GetString("cluster-name")+"/"+*masterInstanceID+"-"+"ca.pem", ca)

			// Associate Master with ELB
			assocMasterWithELB(elbSvc, masterInstanceID)
		}

		// Drop in kube config for laptop user
		kubeConfigValues := userKubeConfig{
			"https://" + *elbDNSName,
			viper.GetString("certificate-path") + "/ca.pem",
			viper.GetString("certificate-path") + "/admin.pem",
			viper.GetString("certificate-path") + "/admin-key.pem",
		}

		generateUserLaptopKubeConfig(kubeConfigValues)
		fmt.Println("kubectl config written to: " + viper.GetString("kube-config-home"))
		fmt.Println("cluster starting up")
		fmt.Println("\n***")
		fmt.Println("To manage with kubectl set the environment variable: export KUBECONFIG=" + viper.GetString("kube-config-home"))
		fmt.Println("***\n")
		generateSkyDNSConfig(kubeConfigValues)
	}

	if *action == "launch-minion" || *action == "init" {
		// Generate User-data for minion.
		minionUserData := generateUserDataFromTemplate(path.Join(viper.GetString("template-path"), "minion-user-data.template"), templateValuesMaster)
		minionUserDataEncoded := base64.StdEncoding.EncodeToString([]byte(minionUserData))

		times, _ := strconv.ParseInt(viper.GetString("minion-cluster-size"), 10, 0)
		var mloop int64
		for mloop = 0; mloop < times; mloop++ {
			// Launch Minion.
			minionPrivateIP, minionInstanceID := launchMinion(svc, minionUserDataEncoded, *instanceProfileArnMinion, vpcID)

			// generate openssl-worker.cnf template in certs dir
			minionSSLSettings := sslConf{
				*minionPrivateIP,
				*elbDNSName,
			}

			// generate minion's keypair
			minionPem, minionKey, minionCa := generateSSL(path.Join(viper.GetString("template-path"), "minion-openssl.cnf.template"),
				minionSSLSettings,
				"./generate_minion_keypair.sh",
				"minion",
			)

			// upload certs to S3
			putObjS3(viper.GetString("cluster-name")+"/"+*minionInstanceID+"-"+"minion.pem", minionPem)
			putObjS3(viper.GetString("cluster-name")+"/"+*minionInstanceID+"-"+"minion-key.pem", minionKey)
			putObjS3(viper.GetString("cluster-name")+"/"+*minionInstanceID+"-"+"ca.pem", minionCa)
		}

		// TODO: this will be moved into a more generic load addons feature as well
		if *action == "init" {
			waitForKubeOperational()
			loadDNSAddon()
		}
	}

	// Success
	fmt.Println("Action: " + *action + " success")
}
