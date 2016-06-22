package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"text/template"

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

func getSecurityGroup(svc *ec2.EC2, kindOf string) *string {
	tagLookup := "Kubernetes" + kindOf
	params := &ec2.DescribeSecurityGroupsInput{
		Filters: []*ec2.Filter{
			{ // Required
				Name: aws.String("tag:KubernetesCluster"),
				Values: []*string{
					aws.String(viper.GetString("cluster-name")),
				},
			},
			{ // Required
				Name: aws.String("tag-key"),
				Values: []*string{
					aws.String(tagLookup),
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
		fmt.Println(err.Error())
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

func launchMaster(svc *ec2.EC2, userData string, instanceProfileArn string) *string {
	masterSecurityGroupID := getSecurityGroup(svc, "Master")

	if masterSecurityGroupID == nil {
		panic("Fatal: could not lookup security groups for this cluster.")
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
			Arn: aws.String(instanceProfileArn),
			//Name: aws.String(viper.GetString("aws-instance-profile-master")),
		},
		InstanceInitiatedShutdownBehavior: aws.String("terminate"),
		InstanceType:                      aws.String("t2.nano"),
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

	// Pretty-print the response data
	return resp.Instances[0].InstanceId
}

func launchMinion(svc *ec2.EC2, userData string, instanceProfileArn string) (*string, *string) {
	securityGroupID := getSecurityGroup(svc, "Minion")

	if securityGroupID == nil {
		panic("Fatal: could not lookup security groups for this cluster.")
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
			Arn: aws.String(instanceProfileArn),
		},
		InstanceInitiatedShutdownBehavior: aws.String("terminate"),
		InstanceType:                      aws.String("t2.micro"),
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
	resp, err := svc.CreateBucket(params)

	if err != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(err.Error())
		fmt.Println("S3 bucket already exists? continuing.")
		return
	}

	// Pretty-print the response data.
	fmt.Println(resp)
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

func generateSSL(fileTemplate string, sslSettings sslConf, generateCommand string, name string) (string, string, string) {
	// generate openssl.cnf template in the certs dir
	templateText, err := ioutil.ReadFile(fileTemplate)
	tmpl, err := template.New("opensslcnf").Parse(string(templateText))
	if err != nil {
		panic(err)
	}

	f, err := os.Create(viper.GetString("certificate-path") + "/" + name + "-openssl.cnf")
	if err != nil {
		log.Println("create file: ", err)
		panic("could not write file")
	}

	err = tmpl.Execute(f, sslSettings)
	if err != nil {
		panic(err)
	}
	f.Close()

	// generate master key with elb's name
	parentDir, _ := os.Getwd()

	os.Chdir(viper.GetString("certificate-path"))

	out, errExec := exec.Command(generateCommand).CombinedOutput()
	if errExec != nil {
		fmt.Println(errExec)
		fmt.Println(out)
		panic("Fatal: error occured while running" + generateCommand)
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

	// Pretty-print the response data.
	if len(resp.Vpcs) == 0 {
		return nil
	}

	//fmt.Println(resp)
	return resp.Vpcs[0].VpcId
}

func createVPCNetworking(svc *ec2.EC2) *string {
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
		return nil
	}

	vpcID := resp.Vpc.VpcId

	fmt.Println("Created VPC: " + *vpcID)

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

	fmt.Println("New route table: " + *rtResp.RouteTables[0].RouteTableId)

	// Tag the VPC and route tables
	_, errtag := svc.CreateTags(&ec2.CreateTagsInput{
		Resources: []*string{vpcID, rtResp.RouteTables[0].RouteTableId},
		Tags: []*ec2.Tag{
			{
				Key:   aws.String("KubernetesCluster"),
				Value: aws.String(viper.GetString("cluster-name")),
			},
		},
	})
	if errtag != nil {
		log.Println("Could not create tags for vpc", *vpcID, errtag)
		return nil
	}
	createSubnets(svc, vpcID)
	addInternetGatewayToVPC(svc, vpcID)

	return vpcID
}

func addInternetGatewayToVPC(svc *ec2.EC2, vpcID *string) {
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
	numAZs := int64(len(descAZResp.AvailabilityZones))

	// Create the subnets
	times, _ := strconv.ParseInt(viper.GetString("num-subnets"), 10, 0)
	var loop int64
	for loop = 0; loop < times; loop++ {
		useAZIndex := loop % numAZs
		fmt.Printf("use az index: %d", useAZIndex)
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
		fmt.Printf("Could not find VPC for KubernetesCluster=%s.  Nothing to do.\n", viper.GetString("cluster-name"))
		return
	}

	fmt.Printf("Tearing down K8S cluster for tag: %s, vpc_id: %s\n", viper.GetString("cluster-name"), *vpcID)
	fmt.Println("Press 'Enter' to continue... CTRL-C to abort.")
	bufio.NewReader(os.Stdin).ReadBytes('\n')

	params := &ec2.DeleteVpcInput{
		VpcId: vpcID,
	}
	resp, err := svc.DeleteVpc(params)

	if err != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(err.Error())
		return
	}

	// Pretty-print the response data.
	fmt.Println(resp)
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
	lookingForName := "kubernetes-" + shortname + "-" + viper.GetString("cluster-name")

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
		//somethingwong
		return nil
	}

	return resp.LoadBalancerDescriptions[0].DNSName
}

func createPolicy(policyTemplateFile string, shortname string) (arn *string) {
	masterTemplateTextBuf, err := ioutil.ReadFile(policyTemplateFile)

	if err != nil {
		fmt.Println("Fatal error: could not read policy templates.")
		os.Exit(1)
	}

	masterTemplateText := string(masterTemplateTextBuf)

	svc := iam.New(session.New())

	params := &iam.CreatePolicyInput{
		PolicyDocument: aws.String(masterTemplateText),
		PolicyName:     aws.String("kubernetes-" + shortname + "-" + viper.GetString("cluster-name")),
		Description:    aws.String("Kubernetes " + shortname + " Instance Policy" + viper.GetString("cluster-name")),
		//Path:           aws.String("/"),
	}
	resp, err := svc.CreatePolicy(params)

	policyArn := resp.Policy.Arn

	if err != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		if err.(awserr.Error).Code() == "EntityAlreadyExists" {
			// Get error details
			fmt.Println("Policy exists, continue.")
			// TODO policyArn =
			// TODO: return policy ARN?
		} else {
			fmt.Println(err.Error())
			os.Exit(1)
		}
	}

	// Pretty-print the response data.
	fmt.Println(resp)

	return policyArn
}

func createRole(policyArn *string, roleName string) (instanceRoleArn *string) {
	svc := iam.New(session.New())
	assumeRoleBuf, err := ioutil.ReadFile("templates/assume-role-policy-document.json")
	assumeRole := string(assumeRoleBuf)

	params := &iam.CreateRoleInput{
		AssumeRolePolicyDocument: aws.String(assumeRole),
		RoleName:                 aws.String(roleName),
		//Path:                     aws.String("pathType"),
	}
	resp, err := svc.CreateRole(params)

	if err != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(err.Error())
		os.Exit(1)
	}

	// Pretty-print the response data.
	fmt.Println(resp)

	params2 := &iam.AttachRolePolicyInput{
		PolicyArn: policyArn, // Required
		RoleName:  aws.String(roleName),
	}
	resp2, err2 := svc.AttachRolePolicy(params2)

	if err2 != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(err2.Error())
		os.Exit(1)
	}

	// Pretty-print the response data.
	fmt.Println(resp2)

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

	// Pretty-print the response data.
	fmt.Println(resp3)

	params4 := &iam.AddRoleToInstanceProfileInput{
		InstanceProfileName: aws.String(roleName), // Required
		RoleName:            aws.String(roleName), // Required
	}
	resp4, err4 := svc.AddRoleToInstanceProfile(params4)

	if err4 != nil {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(err.Error())
		os.Exit(1)
	}

	// Pretty-print the response data.
	fmt.Println(resp4)

	return iArn
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

	// Pretty-print the response data.
	fmt.Println(resp)

	securityGroupID = resp.GroupId

	// Tag with the necessary tags
	_, errtag := svc.CreateTags(&ec2.CreateTagsInput{
		Resources: []*string{securityGroupID},
		Tags: []*ec2.Tag{
			{
				Key:   aws.String("KubernetesCluster"),
				Value: aws.String(viper.GetString("cluster-name")),
			},
			{
				Key:   aws.String("Kubernetes" + kindOf),
				Value: aws.String(""),
			},
		},
	})
	if errtag != nil {
		log.Println("Could not create tags for security group", *vpcID, errtag)
		os.Exit(1)
	}

	return securityGroupID
}

func createELB(svc *ec2.EC2, elbsvc *elb.ELB, vpcID *string) (elbDNSName *string) {

	// Create or lookup elb security group
	securityGroupID := getSecurityGroup(svc, "ELB")

	if securityGroupID == nil {
		fmt.Printf("Creating security group for Kubernetes Master ELB.")
		securityGroupID = createSecurityGroup(svc, "ELB", vpcID)
	}

	// Create ELB
	params := &elb.CreateLoadBalancerInput{
		Listeners: []*elb.Listener{
			{
				InstancePort:     aws.Int64(443),
				LoadBalancerPort: aws.Int64(6443),
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

	// Pretty-print the response data.
	fmt.Println(resp)

	return resp.DNSName

}

func main() {
	// Viper configuration engine
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	viper.SetEnvPrefix("BB")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}

	// Flags
	var action = flag.String("action", "", "Action can be: init, launch-minion")
	flag.Parse()
	switch *action {
	case "":
		panic("Please specify an action: init, launch-minion")
	case "init":
	case "launch-minion":
	case "delete":
	default:
		panic("Please specify an action: init, launch-minion, delete")
	}

	svc := ec2.New(session.New(), &aws.Config{Region: aws.String(viper.GetString("region"))})
	elbSvc := elb.New(session.New(), &aws.Config{Region: aws.String(viper.GetString("region"))})

	if *action == "delete" {
		//teardown VPC
		deleteVPC(svc)
		fmt.Println("Kubernetes assets deleted successfully.")
		os.Exit(0)
	}
	// Things to create if not exists:
	// VPC (this also creates a RouteTable)
	// RouteTable
	// Subnets
	vpcID := detectVPC(svc)
	if vpcID == nil {
		vpcID = createVPCNetworking(svc)
	}

	// Ensure RouteTable (sanity check pre-launch)
	// TODO: no longer necessary?
	//if ensureRouteTable(svc) != true {
	//	panic("Fatal: could not lookup RouteTable for this cluster.")
	//}

	// IAM Roles for Master and Minion
	masterArn := checkPolicy("master")
	if masterArn == nil {
		masterArn = createPolicy("templates/kube-master-iam-policy.json", "master")
	}

	minionArn := checkPolicy("minion")
	if minionArn == nil {
		minionArn = createPolicy("templates/kube-minion-iam-policy.json", "minion")
	}

	masterRoleName := "kubernetes-master-" + viper.GetString("cluster-name")
	instanceProfileArnMaster := checkRole(masterRoleName)
	if instanceProfileArnMaster == nil {
		instanceProfileArnMaster = createRole(masterArn, masterRoleName)
	}

	minionRoleName := "kubernetes-minion-" + viper.GetString("cluster-name")
	instanceProfileArnMinion := checkRole(minionRoleName)
	if instanceProfileArnMinion == nil {
		instanceProfileArnMinion = createRole(minionArn, minionRoleName)
	}

	fmt.Printf("instance profile arns: %s, %s\n", *instanceProfileArnMaster, *instanceProfileArnMinion)

	// S3 Bucket for certs
	createS3Bucket()

	// Sanity check S3 permission by writing test.
	if putObjS3("preflight-check1.0", "preflight-check") == false {
		panic("Fatal: Unable to write to s3 bucket.  Please check permissions and try again.")
	}

	// TODO: needs Internet Gateway

	// ELB for master nodes
	elbDNSName := getELBDNSName(elbSvc)
	if elbDNSName == nil {
		fmt.Printf("Creating ELB for %s", viper.GetString("elb-name"))
		elbDNSName = createELB(svc, elbSvc, vpcID)
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
		masterUserData := generateUserDataFromTemplate("master-user-data.template", templateValuesMaster)
		masterUserDataEncoded := base64.StdEncoding.EncodeToString([]byte(masterUserData))

		// Launch Master(s)
		times, _ := strconv.ParseInt(viper.GetString("master-cluster-size"), 10, 0)
		var mloop int64
		for mloop = 0; mloop < times; mloop++ {
			masterInstanceID := launchMaster(svc, masterUserDataEncoded, *instanceProfileArnMaster)

			masterSSLSettings := sslConf{
				"", //un-necessary on master
				*elbDNSName,
			}

			apiPem, apiKey, ca := generateSSL("master-openssl.cnf.template",
				masterSSLSettings,
				"./generate_api_keypair.sh",
				"apiserver",
			)

			// upload certs to S3
			putObjS3(*masterInstanceID+"-"+"apiserver.pem", apiPem)
			putObjS3(*masterInstanceID+"-"+"apiserver-key.pem", apiKey)
			putObjS3(*masterInstanceID+"-"+"ca.pem", ca)
			// Instance Tags?

			// Associate Master with ELB
			assocMasterWithELB(elbSvc, masterInstanceID)
		}
	}

	if *action == "launch-minion" {
		// Generate User-data for minion.
		minionUserData := generateUserDataFromTemplate("minion-user-data.template", templateValuesMaster)
		minionUserDataEncoded := base64.StdEncoding.EncodeToString([]byte(minionUserData))

		times, _ := strconv.ParseInt(viper.GetString("minion-cluster-size"), 10, 0)
		var mloop int64
		for mloop = 0; mloop < times; mloop++ {
			// Launch Minion.
			minionPrivateIP, minionInstanceID := launchMinion(svc, minionUserDataEncoded, *instanceProfileArnMinion)

			// generate openssl-worker.cnf template in certs dir
			minionSSLSettings := sslConf{
				*minionPrivateIP,
				*elbDNSName,
			}

			// generate minion's keypair
			minionPem, minionKey, minionCa := generateSSL("minion-openssl.cnf.template",
				minionSSLSettings,
				"./generate_minion_keypair.sh",
				"minion",
			)

			// upload certs to S3
			putObjS3(*minionInstanceID+"-"+"minion.pem", minionPem)
			putObjS3(*minionInstanceID+"-"+"minion-key.pem", minionKey)
			putObjS3(*minionInstanceID+"-"+"ca.pem", minionCa)
		}
	}

	// Success
	fmt.Println("Action: " + *action + " success")
}
