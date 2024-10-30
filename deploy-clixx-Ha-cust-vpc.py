#!/usr/bin/env python3
import boto3, botocore, base64, time

# Assume Role to interact with AWS resources
sts_client = boto3.client('sts')
assumed_role_object = sts_client.assume_role(
    RoleArn='arn:aws:iam::043309319757:role/Engineer',
    RoleSessionName='mysession'
)
credentials = assumed_role_object['Credentials']

# Create boto3 clients with assumed role credentials
ec2_client = boto3.client('ec2', region_name="us-east-1", 
                          aws_access_key_id=credentials['AccessKeyId'], 
                          aws_secret_access_key=credentials['SecretAccessKey'], 
                          aws_session_token=credentials['SessionToken'])

ec2_resource = boto3.resource('ec2', region_name="us-east-1",
                            aws_access_key_id=credentials['AccessKeyId'],
                            aws_secret_access_key=credentials['SecretAccessKey'],
                            aws_session_token=credentials['SessionToken'])

elbv2_client = boto3.client('elbv2', region_name="us-east-1", 
                            aws_access_key_id=credentials['AccessKeyId'], 
                            aws_secret_access_key=credentials['SecretAccessKey'], 
                            aws_session_token=credentials['SessionToken'])

rds_client = boto3.client('rds', region_name="us-east-1", 
                          aws_access_key_id=credentials['AccessKeyId'], 
                          aws_secret_access_key=credentials['SecretAccessKey'], 
                          aws_session_token=credentials['SessionToken'])

efs_client = boto3.client('efs', region_name="us-east-1", 
                          aws_access_key_id=credentials['AccessKeyId'], 
                          aws_secret_access_key=credentials['SecretAccessKey'], 
                          aws_session_token=credentials['SessionToken'])

route53_client = boto3.client('route53', 
                              aws_access_key_id=credentials['AccessKeyId'], 
                              aws_secret_access_key=credentials['SecretAccessKey'], 
                              aws_session_token=credentials['SessionToken'])

autoscaling_client = boto3.client('autoscaling', region_name="us-east-1", 
                                  aws_access_key_id=credentials['AccessKeyId'], 
                                  aws_secret_access_key=credentials['SecretAccessKey'], 
                                  aws_session_token=credentials['SessionToken'])

###########################################################################
# Variables
vpc_cidr_block = "10.0.0.0/16"
priv_sub1_cidr_block_app_db = "10.0.0.0/22"
priv_sub2_cidr_block_app_db = "10.0.4.0/22"
priv_sub1_cidr_block_oracle_db = "10.0.9.0/24"
priv_sub2_cidr_block_oracle_db = "10.0.10.0/24"
priv_sub1_cidr_block_webapp = "10.0.11.0/24"
priv_sub2_cidr_block_webapp = "10.0.12.0/24"
priv_sub1_cidr_block_java_db = "10.0.13.0/26"
priv_sub2_cidr_block_java_db = "10.0.13.64/26"
priv_sub1_cidr_block_java_app = "10.0.13.128/26"
priv_sub2_cidr_block_java_app = "10.0.13.192/26"
pub_sub1_cidr_block = "10.0.14.0/25"
pub_sub2_cidr_block = "10.0.14.128/25"
pub_az_1 = "us-east-1a"
pub_az_2 = "us-east-1b"
priv_az_1 = "us-east-1a"
priv_az_2 = "us-east-1b"
db_instance_identifier = "Wordpressdbclixx"
db_snapshot_identifier = "arn:aws:rds:us-east-1:043309319757:snapshot:wordpressdbclixx-ecs-snapshot-copy"
db_instance_class = "db.m6gd.large"
db_username = "wordpressuser"
db_password = "W3lcome123"
ami_id = "ami-00f251754ac5da7f0"
instance_type = "t2.micro"
key_pair_name = "stack_devops_kp"
certificate_arn = "arn:aws:acm:us-east-1:043309319757:certificate/1e2f9427-2612-4811-9eb9-682ef736ad48"
hosted_zone_id = "Z022607324NJ585R59I5F"
record_name = "test.clixx-wdella.com"
aws_region = "us-east-1"

# --- VPC ---
vpcs = ec2_client.describe_vpcs(Filters=[{'Name': 'cidr', 'Values': [vpc_cidr_block]}])
if not vpcs['Vpcs']:
    vpc = ec2_resource.create_vpc(CidrBlock=vpc_cidr_block)
    ec2_client.create_tags(Resources=[vpc.id], Tags=[{'Key': 'Name', 'Value': 'MYSTACKVPC'}])
    ec2_client.modify_vpc_attribute(VpcId=vpc.id, EnableDnsSupport={'Value': True})
    ec2_client.modify_vpc_attribute(VpcId=vpc.id, EnableDnsHostnames={'Value': True})
    print(f"VPC created: {vpc.id} with Name tag 'MYSTACKVPC'")
else:
    print(f"VPC already exists with CIDR block {vpc_cidr_block}")
vpc_id = vpcs['Vpcs'][0]['VpcId'] if vpcs['Vpcs'] else vpc.id

# --- Public and Private Subnet ---
# Create Public Subnets for load balancer
public_subnet1 = ec2_client.describe_subnets(Filters=[{'Name': 'cidrBlock', 'Values': [pub_sub1_cidr_block]}])
if not public_subnet1['Subnets']:
    public_subnet1_response = ec2_client.create_subnet(VpcId=vpc_id, CidrBlock=pub_sub1_cidr_block, AvailabilityZone=pub_az_1)
    public_subnet1_id = public_subnet1_response['Subnet']['SubnetId']  # Correctly get the SubnetId
    ec2_client.create_tags(Resources=[public_subnet1_id], Tags=[{'Key': 'Name', 'Value': 'MYSTACKPUBSUB1'}])
    print(f"Public Subnet created: {public_subnet1_id} with Name tag 'MYSTACKPUBSUB1'")
else:
    public_subnet1_id = public_subnet1['Subnets'][0]['SubnetId']  # Assign existing subnet ID
    print(f"Public Subnet already exists with CIDR block {pub_sub1_cidr_block}, ID: {public_subnet1_id}")

public_subnet2 = ec2_client.describe_subnets(Filters=[{'Name': 'cidrBlock', 'Values': [pub_sub2_cidr_block]}])
if not public_subnet2['Subnets']:  # Change to public_subnet2
    public_subnet2_response = ec2_client.create_subnet(VpcId=vpc_id, CidrBlock=pub_sub2_cidr_block, AvailabilityZone=pub_az_2)
    public_subnet2_id = public_subnet2_response['Subnet']['SubnetId']  # Correctly get the SubnetId
    ec2_client.create_tags(Resources=[public_subnet2_id], Tags=[{'Key': 'Name', 'Value': 'MYSTACKPUBSUB2'}])
    print(f"Public Subnet created: {public_subnet2_id} with Name tag 'MYSTACKPUBSUB2'")
else:
    public_subnet2_id = public_subnet2['Subnets'][0]['SubnetId']  # Assign existing subnet ID
    print(f"Public Subnet already exists with CIDR block {pub_sub2_cidr_block}, ID: {public_subnet2_id}")

# Create Private Subnets for Web Application
private_subnet1_webapp = ec2_client.describe_subnets(Filters=[{'Name': 'cidrBlock', 'Values': [priv_sub1_cidr_block_webapp]}, {'Name': 'vpc-id', 'Values': [vpc_id]}])
if not private_subnet1_webapp['Subnets']:
    private_subnet1_webapp_response = ec2_client.create_subnet(VpcId=vpc_id, CidrBlock=priv_sub1_cidr_block_webapp, AvailabilityZone=priv_az_1)
    private_subnet1_webapp_id = private_subnet1_webapp_response['Subnet']['SubnetId']  # Correctly get the SubnetId
    ec2_client.create_tags(Resources=[private_subnet1_webapp_id], Tags=[{'Key': 'Name', 'Value': 'MYSTACKPRIVSUB1-WEBAPP'}])
    print(f"Private Subnet created: {private_subnet1_webapp_id} with Name tag 'MYSTACKPRIVSUB1-WEBAPP'")
else:
    private_subnet1_webapp_id = private_subnet1_webapp['Subnets'][0]['SubnetId']  # Assign existing subnet ID
    print(f"Private Subnet already exists with CIDR block {priv_sub1_cidr_block_webapp}, ID: {private_subnet1_webapp_id}")

private_subnet2_webapp = ec2_client.describe_subnets(Filters=[{'Name': 'cidrBlock', 'Values': [priv_sub2_cidr_block_webapp]}, {'Name': 'vpc-id', 'Values': [vpc_id]}])
if not private_subnet2_webapp['Subnets']:
    private_subnet2_webapp_response = ec2_client.create_subnet(VpcId=vpc_id, CidrBlock=priv_sub2_cidr_block_webapp, AvailabilityZone=priv_az_2)
    private_subnet2_webapp_id = private_subnet2_webapp_response['Subnet']['SubnetId']  # Correctly get the SubnetId
    ec2_client.create_tags(Resources=[private_subnet2_webapp_id], Tags=[{'Key': 'Name', 'Value': 'MYSTACKPRIVSUB2-WEBAPP'}])
    print(f"Private Subnet created: {private_subnet2_webapp_id} with Name tag 'MYSTACKPRIVSUB2-WEBAPP'")
else:
    private_subnet2_webapp_id = private_subnet2_webapp['Subnets'][0]['SubnetId']  # Assign existing subnet ID
    print(f"Private Subnet already exists with CIDR block {priv_sub2_cidr_block_webapp}, ID: {private_subnet2_webapp_id}")

# Create Private Subnets for Application Databases
private_subnet1_app_db = ec2_client.describe_subnets(Filters=[{'Name': 'cidrBlock', 'Values': [priv_sub1_cidr_block_app_db]}, {'Name': 'vpc-id', 'Values': [vpc_id]}])
if 'Subnets' not in private_subnet1_app_db or not private_subnet1_app_db['Subnets']:
    private_subnet1_app_db = ec2_client.create_subnet(VpcId=vpc_id, CidrBlock=priv_sub1_cidr_block_app_db, AvailabilityZone=priv_az_1)
    ec2_client.create_tags(Resources=[private_subnet1_app_db['Subnet']['SubnetId']], Tags=[{'Key': 'Name', 'Value': 'MYSTACKPRIVSUB1-APPDB'}])
    print(f"Private Subnet created: {private_subnet1_app_db['Subnet']['SubnetId']} with Name tag 'MYSTACKPRIVSUB1-APPDB'")
    private_subnet1_app_db_id = private_subnet1_app_db['Subnet']['SubnetId']
else:
    print(f"Private Subnet already exists with CIDR block {priv_sub1_cidr_block_app_db}")
    private_subnet1_app_db_id = private_subnet1_app_db['Subnets'][0]['SubnetId']

private_subnet2_app_db = ec2_client.describe_subnets(Filters=[{'Name': 'cidrBlock', 'Values': [priv_sub2_cidr_block_app_db]}, {'Name': 'vpc-id', 'Values': [vpc_id]}])
if 'Subnets' not in private_subnet2_app_db or not private_subnet2_app_db['Subnets']:
    private_subnet2_app_db = ec2_client.create_subnet(VpcId=vpc_id, CidrBlock=priv_sub2_cidr_block_app_db, AvailabilityZone=priv_az_2)
    ec2_client.create_tags(Resources=[private_subnet2_app_db['Subnet']['SubnetId']], Tags=[{'Key': 'Name', 'Value': 'MYSTACKPRIVSUB2-APPDB'}])
    print(f"Private Subnet created: {private_subnet2_app_db['Subnet']['SubnetId']} with Name tag 'MYSTACKPRIVSUB2-APPDB'")
    private_subnet2_app_db_id = private_subnet2_app_db['Subnet']['SubnetId']
else:
    print(f"Private Subnet already exists with CIDR block {priv_sub2_cidr_block_app_db}")
    private_subnet2_app_db_id = private_subnet2_app_db['Subnets'][0]['SubnetId']

# Create Private Subnets for Oracle Databases
private_subnet1_oracle_db = ec2_client.describe_subnets(Filters=[{'Name': 'cidrBlock', 'Values': [priv_sub1_cidr_block_oracle_db]}, {'Name': 'vpc-id', 'Values': [vpc_id]}])
if 'Subnets' not in private_subnet1_oracle_db or not private_subnet1_oracle_db['Subnets']:
    private_subnet1_oracle_db = ec2_client.create_subnet(VpcId=vpc_id, CidrBlock=priv_sub1_cidr_block_oracle_db, AvailabilityZone=priv_az_1)
    ec2_client.create_tags(Resources=[private_subnet1_oracle_db['Subnet']['SubnetId']], Tags=[{'Key': 'Name', 'Value': 'MYSTACKPRIVSUB1-ORADB'}])
    print(f"Private Subnet created: {private_subnet1_oracle_db['Subnet']['SubnetId']} with Name tag 'MYSTACKPRIVSUB1-ORADB'")
    private_subnet1_oracle_db_id = private_subnet1_oracle_db['Subnet']['SubnetId']
else:
    print(f"Private Subnet already exists with CIDR block {priv_sub1_cidr_block_oracle_db}")
    private_subnet1_oracle_db_id = private_subnet1_oracle_db['Subnets'][0]['SubnetId']

private_subnet2_oracle_db = ec2_client.describe_subnets(Filters=[{'Name': 'cidrBlock', 'Values': [priv_sub2_cidr_block_oracle_db]}, {'Name': 'vpc-id', 'Values': [vpc_id]}])
if 'Subnets' not in private_subnet2_oracle_db or not private_subnet2_oracle_db['Subnets']:
    private_subnet2_oracle_db = ec2_client.create_subnet(VpcId=vpc_id, CidrBlock=priv_sub2_cidr_block_oracle_db, AvailabilityZone=priv_az_2)
    ec2_client.create_tags(Resources=[private_subnet2_oracle_db['Subnet']['SubnetId']], Tags=[{'Key': 'Name', 'Value': 'MYSTACKPRIVSUB2-ORADB'}])
    print(f"Private Subnet created: {private_subnet2_oracle_db['Subnet']['SubnetId']} with Name tag 'MYSTACKPRIVSUB2-ORADB'")
    private_subnet2_oracle_db_id = private_subnet2_oracle_db['Subnet']['SubnetId']
else:
    print(f"Private Subnet already exists with CIDR block {priv_sub2_cidr_block_oracle_db}")
    private_subnet2_oracle_db_id = private_subnet2_oracle_db['Subnets'][0]['SubnetId']

# Create Private Subnets for Java Application and Databases
private_subnet1_java_db = ec2_client.describe_subnets(Filters=[{'Name': 'cidrBlock', 'Values': [priv_sub1_cidr_block_java_db]}, {'Name': 'vpc-id', 'Values': [vpc_id]}])
if 'Subnets' not in private_subnet1_java_db or not private_subnet1_java_db['Subnets']:
    private_subnet1_java_db = ec2_client.create_subnet(VpcId=vpc_id, CidrBlock=priv_sub1_cidr_block_java_db, AvailabilityZone=priv_az_1)
    ec2_client.create_tags(Resources=[private_subnet1_java_db['Subnet']['SubnetId']], Tags=[{'Key': 'Name', 'Value': 'MYSTACKPRIVSUB1-JAVADB'}])
    print(f"Private Subnet created: {private_subnet1_java_db['Subnet']['SubnetId']} with Name tag 'MYSTACKPRIVSUB1-JAVADB'")
    private_subnet1_java_db_id = private_subnet1_java_db['Subnet']['SubnetId']
else:
    print(f"Private Subnet already exists with CIDR block {priv_sub1_cidr_block_java_db}")
    private_subnet1_java_db_id = private_subnet1_java_db['Subnets'][0]['SubnetId']

private_subnet2_java_db = ec2_client.describe_subnets(Filters=[{'Name': 'cidrBlock', 'Values': [priv_sub2_cidr_block_java_db]}, {'Name': 'vpc-id', 'Values': [vpc_id]}])
if 'Subnets' not in private_subnet2_java_db or not private_subnet2_java_db['Subnets']:
    private_subnet2_java_db = ec2_client.create_subnet(VpcId=vpc_id, CidrBlock=priv_sub2_cidr_block_java_db, AvailabilityZone=priv_az_2)
    ec2_client.create_tags(Resources=[private_subnet2_java_db['Subnet']['SubnetId']], Tags=[{'Key': 'Name', 'Value': 'MYSTACKPRIVSUB2-JAVADB'}])
    print(f"Private Subnet created: {private_subnet2_java_db['Subnet']['SubnetId']} with Name tag 'MYSTACKPRIVSUB2-JAVADB'")
    private_subnet2_java_db_id = private_subnet2_java_db['Subnet']['SubnetId']
else:
    print(f"Private Subnet already exists with CIDR block {priv_sub2_cidr_block_java_db}")
    private_subnet2_java_db_id = private_subnet2_java_db['Subnets'][0]['SubnetId']

# Create Private Subnets for Java Applications
private_subnet1_java_app = ec2_client.describe_subnets(
    Filters=[{'Name': 'cidrBlock', 'Values': [priv_sub1_cidr_block_java_app]}, {'Name': 'vpc-id', 'Values': [vpc_id]}])
# Check if the response is valid and contains 'Subnets'
if 'Subnets' in private_subnet1_java_app and private_subnet1_java_app['Subnets']:
    private_subnet1_java_app_id = private_subnet1_java_app['Subnets'][0]['SubnetId']
    print(f"Private Subnet already exists with ID: {private_subnet1_java_app_id}")
else:
    # Create the subnet if it does not exist
    private_subnet1_java_app = ec2_client.create_subnet(VpcId=vpc_id, CidrBlock=priv_sub1_cidr_block_java_app, AvailabilityZone=priv_az_1)
    ec2_client.create_tags(Resources=[private_subnet1_java_app['Subnet']['SubnetId']], Tags=[{'Key': 'Name', 'Value': 'MYSTACKPRIVSUB1-JAVAAPP'}])
    private_subnet1_java_app_id = private_subnet1_java_app['Subnet']['SubnetId']
    print(f"Private Subnet created: {private_subnet1_java_app_id} with Name tag 'MYSTACKPRIVSUB1-JAVAAPP'")

private_subnet2_java_app = ec2_client.describe_subnets(
    Filters=[{'Name': 'cidrBlock', 'Values': [priv_sub2_cidr_block_java_app]}, {'Name': 'vpc-id', 'Values': [vpc_id]}])
if 'Subnets' in private_subnet2_java_app and private_subnet2_java_app['Subnets']:
    private_subnet2_java_app_id = private_subnet2_java_app['Subnets'][0]['SubnetId']
    print(f"Private Subnet already exists with ID: {private_subnet2_java_app_id}")
else:
    private_subnet2_java_app = ec2_client.create_subnet(VpcId=vpc_id, CidrBlock=priv_sub2_cidr_block_java_app, AvailabilityZone=priv_az_2)
    ec2_client.create_tags(Resources=[private_subnet2_java_app['Subnet']['SubnetId']], Tags=[{'Key': 'Name', 'Value': 'MYSTACKPRIVSUB2-JAVAAPP'}])
    private_subnet2_java_app_id = private_subnet2_java_app['Subnet']['SubnetId']
    print(f"Private Subnet created: {private_subnet2_java_app_id} with Name tag 'MYSTACKPRIVSUB2-JAVAAPP'")

## --- Internet Gateway ---
internet_gateway = ec2_client.describe_internet_gateways(Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}])

if not internet_gateway['InternetGateways']:
    igw = ec2_resource.create_internet_gateway()
    ec2_client.attach_internet_gateway(InternetGatewayId=igw.id, VpcId=vpc_id)
    ec2_client.create_tags(Resources=[igw.id], Tags=[{'Key': 'Name', 'Value': 'MYSTACKIGW'}])
    print(f"Internet Gateway created: {igw.id} with Name tag 'MYSTACKIGW'")
    internet_gateway_id = igw.id  
else:
    print(f"Internet Gateway already exists for VPC {vpc_id}")
    internet_gateway_id = internet_gateway['InternetGateways'][0]['InternetGatewayId'] 

# --- Elastic IPs for NAT Gateways ---
# For NAT EIP 1
nat_eip1_response = ec2_client.describe_addresses(Filters=[{'Name': 'tag:Name', 'Values': ['MYSTACKNAT-EIP1']}])
if not nat_eip1_response['Addresses']:
    nat_eip1_response = ec2_client.allocate_address(Domain='vpc')
    ec2_client.create_tags(Resources=[nat_eip1_response['AllocationId']], Tags=[{'Key': 'Name', 'Value': 'MYSTACKNAT-EIP1'}])
    print(f"NAT Elastic IP created: {nat_eip1_response['PublicIp']} with Name tag 'MYSTACKNAT-EIP1'")
    nat_eip1_id = nat_eip1_response['AllocationId']  
else:
    print(f"NAT Elastic IP already exists with Name tag 'MYSTACKNAT-EIP1'")
    nat_eip1_id = nat_eip1_response['Addresses'][0]['AllocationId']

# For NAT EIP 2
nat_eip2_response = ec2_client.describe_addresses(Filters=[{'Name': 'tag:Name', 'Values': ['MYSTACKNAT-EIP2']}])
if not nat_eip2_response['Addresses']:
    nat_eip2_response = ec2_client.allocate_address(Domain='vpc')
    ec2_client.create_tags(Resources=[nat_eip2_response['AllocationId']], Tags=[{'Key': 'Name', 'Value': 'MYSTACKNAT-EIP2'}])
    print(f"NAT Elastic IP created: {nat_eip2_response['PublicIp']} with Name tag 'MYSTACKNAT-EIP2'")
    nat_eip2_id = nat_eip2_response['AllocationId']  
else:
    print(f"NAT Elastic IP already exists with Name tag 'MYSTACKNAT-EIP2'")
    nat_eip2_id = nat_eip2_response['Addresses'][0]['AllocationId']

# --- NAT Gateways ---
# For NAT Gateway 1
nat_gateway1_response = ec2_client.describe_nat_gateways(Filters=[{'Name': 'tag:Name', 'Values': ['MYSTACKNAT-GW1']}])
if not nat_gateway1_response['NatGateways']:
    nat_gateway1_response = ec2_client.create_nat_gateway(AllocationId=nat_eip1_id, SubnetId=public_subnet1_id)
    ec2_client.create_tags(Resources=[nat_gateway1_response['NatGateway']['NatGatewayId']], Tags=[{'Key': 'Name', 'Value': 'MYSTACKNAT-GW1'}])
    print(f"NAT Gateway created: {nat_gateway1_response['NatGateway']['NatGatewayId']} with Name tag 'MYSTACKNAT-GW1'")
    nat_gateway1_id = nat_gateway1_response['NatGateway']['NatGatewayId'] 
else:
    print(f"NAT Gateway already exists with Name tag 'MYSTACKNAT-GW1'")
    nat_gateway1_id = nat_gateway1_response['NatGateways'][0]['NatGatewayId']

# Debugging: Print the value of public_subnet2_id
print(f"Public Subnet 2 ID: {public_subnet2_id}")
# For NAT Gateway 2
nat_gateway2_response = ec2_client.describe_nat_gateways(Filters=[{'Name': 'tag:Name', 'Values': ['MYSTACKNAT-GW2']}])
if not nat_gateway2_response['NatGateways']:
    if public_subnet2_id is not None:
        nat_gateway2_response = ec2_client.create_nat_gateway(AllocationId=nat_eip2_id, SubnetId=public_subnet2_id)
        ec2_client.create_tags(Resources=[nat_gateway2_response['NatGateway']['NatGatewayId']], Tags=[{'Key': 'Name', 'Value': 'MYSTACKNAT-GW2'}])
        print(f"NAT Gateway created: {nat_gateway2_response['NatGateway']['NatGatewayId']} with Name tag 'MYSTACKNAT-GW2'")
        nat_gateway2_id = nat_gateway2_response['NatGateway']['NatGatewayId']  # Use the id directly
    else:
        print("Error: public_subnet2_id is None. Please check the subnet ID assignment.")
else:
    print(f"NAT Gateway already exists with Name tag 'MYSTACKNAT-GW2'")
    nat_gateway2_id = nat_gateway2_response['NatGateways'][0]['NatGatewayId']

# --- Public Route Tables ---
# Public Route Table 1
pub_rt1_response = ec2_client.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}, {'Name': 'tag:Name', 'Values': ['MYSTACKPUB-RT1']}])
if not pub_rt1_response['RouteTables']:
    pub_rt1 = ec2_resource.create_route_table(VpcId=vpc_id)
    ec2_client.create_route(DestinationCidrBlock='0.0.0.0/0', GatewayId=internet_gateway_id, RouteTableId=pub_rt1.id)
    ec2_client.create_tags(Resources=[pub_rt1.id], Tags=[{'Key': 'Name', 'Value': 'MYSTACKPUB-RT1'}])
    print(f"Public Route Table 1 created: {pub_rt1.id} with Name tag 'MYSTACKPUB-RT1'")
    pub_rt1_id = pub_rt1.id  # Use the id directly
else:
    print(f"Public Route Table 1 already exists: {pub_rt1_response['RouteTables'][0]['RouteTableId']}")
    pub_rt1_id = pub_rt1_response['RouteTables'][0]['RouteTableId']
# Public Route Table 2
pub_rt2_response = ec2_client.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}, {'Name': 'tag:Name', 'Values': ['MYSTACKPUB-RT2']}])
if not pub_rt2_response['RouteTables']:
    pub_rt2 = ec2_resource.create_route_table(VpcId=vpc_id)
    ec2_client.create_route(DestinationCidrBlock='0.0.0.0/0', GatewayId=internet_gateway_id, RouteTableId=pub_rt2.id)
    ec2_client.create_tags(Resources=[pub_rt2.id], Tags=[{'Key': 'Name', 'Value': 'MYSTACKPUB-RT2'}])
    print(f"Public Route Table 2 created: {pub_rt2.id} with Name tag 'MYSTACKPUB-RT2'")
    pub_rt2_id = pub_rt2.id  # Use the id directly
else:
    print(f"Public Route Table 2 already exists: {pub_rt2_response['RouteTables'][0]['RouteTableId']}")
    pub_rt2_id = pub_rt2_response['RouteTables'][0]['RouteTableId']

# --- Route Table Associations for Public Route Table 1 ---
assoc_pub_rt1_response = ec2_client.describe_route_tables(RouteTableIds=[pub_rt1_id])
if assoc_pub_rt1_response['RouteTables']:
    for association in assoc_pub_rt1_response['RouteTables'][0].get('Associations', []):
        if association['SubnetId'] == public_subnet1_id:
            print(f"Route Table Association already exists for Public Route Table 1 and subnet {public_subnet1_id}")
            break
    else:
        ec2_client.associate_route_table(RouteTableId=pub_rt1_id, SubnetId=public_subnet1_id)
        print(f"Route Table Association created for Public Route Table 1 and subnet {public_subnet1_id}")

# --- Route Table Associations for Public Route Table 2 ---
assoc_pub_rt2_response = ec2_client.describe_route_tables(RouteTableIds=[pub_rt2_id])
if assoc_pub_rt2_response['RouteTables']:
    for association in assoc_pub_rt2_response['RouteTables'][0].get('Associations', []):
        if association['SubnetId'] == public_subnet2_id:
            print(f"Route Table Association already exists for Public Route Table 2 and subnet {public_subnet2_id}")
            break
    else:
        ec2_client.associate_route_table(RouteTableId=pub_rt2_id, SubnetId=public_subnet2_id)
        print(f"Route Table Association created for Public Route Table 2 and subnet {public_subnet2_id}")

# --- Private Route Tables ---
# Private Route Table 1
priv_rt1_response = ec2_client.describe_route_tables(
    Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}, {'Name': 'tag:Name', 'Values': ['MYSTACKPRIV-RT1']}]
)
if not priv_rt1_response['RouteTables']:
    priv_rt1 = ec2_resource.create_route_table(VpcId=vpc_id)
    ec2_client.create_tags(Resources=[priv_rt1.id], Tags=[{'Key': 'Name', 'Value': 'MYSTACKPRIV-RT1'}])
    print(f"Private Route Table 1 created: {priv_rt1.id} with Name tag 'MYSTACKPRIV-RT1'")
    priv_rt1_id = priv_rt1.id  # Use the id directly
else:
    print(f"Private Route Table 1 already exists: {priv_rt1_response['RouteTables'][0]['RouteTableId']}")
    priv_rt1_id = priv_rt1_response['RouteTables'][0]['RouteTableId']

# --- Route Table Associations for Private Route Table 1 ---
for subnet_id in [private_subnet1_webapp_id, private_subnet1_app_db_id, private_subnet1_oracle_db_id, private_subnet1_java_db_id, private_subnet1_java_app_id]:
    priv_rt1_response = ec2_client.describe_route_tables(RouteTableIds=[priv_rt1_id])
    if priv_rt1_response['RouteTables']:
        for association in priv_rt1_response['RouteTables'][0].get('Associations', []):
            if association['SubnetId'] == subnet_id:
                print(f"Route Table Association already exists for Private Route Table 1 and subnet {subnet_id}")
                break
        else:
            ec2_client.associate_route_table(RouteTableId=priv_rt1_id, SubnetId=subnet_id)
            print(f"Route Table Association created for Private Route Table 1 and subnet {subnet_id}")

# Private Route Table 2
priv_rt2_response = ec2_client.describe_route_tables(
    Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}, {'Name': 'tag:Name', 'Values': ['MYSTACKPRIV-RT2']}]
)
if not priv_rt2_response['RouteTables']:
    priv_rt2 = ec2_resource.create_route_table(VpcId=vpc_id)
    ec2_client.create_tags(Resources=[priv_rt2.id], Tags=[{'Key': 'Name', 'Value': 'MYSTACKPRIV-RT2'}])
    print(f"Private Route Table 2 created: {priv_rt2.id} with Name tag 'MYSTACKPRIV-RT2'")
    priv_rt2_id = priv_rt2.id  # Use the id directly
else:
    print(f"Private Route Table 2 already exists: {priv_rt2_response['RouteTables'][0]['RouteTableId']}")
    priv_rt2_id = priv_rt2_response['RouteTables'][0]['RouteTableId']

# --- Route Table Associations for Private Route Table 2 ---
for subnet_id in [private_subnet2_webapp_id, private_subnet2_app_db_id, private_subnet2_oracle_db_id, private_subnet2_java_db_id, private_subnet2_java_app_id]:
    priv_rt2_response = ec2_client.describe_route_tables(RouteTableIds=[priv_rt2_id])
    if priv_rt2_response['RouteTables']:
        for association in priv_rt2_response['RouteTables'][0].get('Associations', []):
            if association['SubnetId'] == subnet_id:
                print(f"Route Table Association already exists for Private Route Table 2 and subnet {subnet_id}")
                break
        else:
            ec2_client.associate_route_table(RouteTableId=priv_rt2_id, SubnetId=subnet_id)
            print(f"Route Table Association created for Private Route Table 2 and subnet {subnet_id}")

# --- Add Routes to Private Route Tables ---
# Route to NAT Gateway 1
private_route1 = ec2_client.describe_route_tables(Filters=[{'Name': 'route-table-id', 'Values': [priv_rt1_id]}])
if private_route1['RouteTables']:
    ec2_client.create_route(RouteTableId=priv_rt1_id, DestinationCidrBlock='0.0.0.0/0', NatGatewayId=nat_gateway1_id)
    print(f"Route added to Private Route Table 1 to NAT Gateway {nat_gateway1_id}")

# Route to NAT Gateway 2
private_route2 = ec2_client.describe_route_tables(Filters=[{'Name': 'route-table-id', 'Values': [priv_rt2_id]}])
if private_route2['RouteTables']:
    ec2_client.create_route(RouteTableId=priv_rt2_id, DestinationCidrBlock='0.0.0.0/0', NatGatewayId=nat_gateway2_id)
    print(f"Route added to Private Route Table 2 to NAT Gateway {nat_gateway2_id}")

# --- Security Group ---
# Define security group names
bastion_sg_name = "MYSTACKBASTION-SG"
pub_sg_name = "MYSTACKPUB-SG"
priv_sg_name = "MYSTACKPRIV-SG"

# Check if Bastion Security Group exists
bastion_sg_response = ec2_client.describe_security_groups(Filters=[{'Name': 'group-name', 'Values': [bastion_sg_name]}])
bastion_sg_id = bastion_sg_response['SecurityGroups'][0]['GroupId'] if bastion_sg_response['SecurityGroups'] else None

if bastion_sg_id is None:
    bastion_sg_response = ec2_client.create_security_group(GroupName=bastion_sg_name, Description='Bastion Security Group', VpcId=vpc_id)
    bastion_sg_id = bastion_sg_response['GroupId']
    ec2_client.authorize_security_group_ingress(GroupId=bastion_sg_id, IpPermissions=[{
        'IpProtocol': 'tcp',
        'FromPort': 22,
        'ToPort': 22,
        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
    }])
    ec2_client.create_tags(Resources=[bastion_sg_id], Tags=[{'Key': 'Name', 'Value': bastion_sg_name}])

# Check if Public Security Group exists
pub_sg_response = ec2_client.describe_security_groups(Filters=[{'Name': 'group-name', 'Values': [pub_sg_name]}])
pub_sg_id = pub_sg_response['SecurityGroups'][0]['GroupId'] if pub_sg_response['SecurityGroups'] else None

if pub_sg_id is None:
    pub_sg_response = ec2_client.create_security_group(GroupName=pub_sg_name, Description='Public Security Group', VpcId=vpc_id)
    pub_sg_id = pub_sg_response['GroupId']
    ec2_client.authorize_security_group_ingress(GroupId=pub_sg_id, IpPermissions=[
        {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'UserIdGroupPairs': [{'GroupId': bastion_sg_id}]},
        {'IpProtocol': 'icmp', 'FromPort': -1, 'ToPort': -1, 'UserIdGroupPairs': [{'GroupId': bastion_sg_id}]},
        {'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
        {'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
        {'IpProtocol': 'tcp', 'FromPort': 3306, 'ToPort': 3306, 'IpRanges': [{'CidrIp': '10.0.0.0/16'}]},
        {'IpProtocol': 'tcp', 'FromPort': 2049, 'ToPort': 2049, 'IpRanges': [{'CidrIp': '10.0.0.0/16'}]}
    ])
    ec2_client.create_tags(Resources=[pub_sg_id], Tags=[{'Key': 'Name', 'Value': pub_sg_name}])

# Check if Private Security Group exists
priv_sg_response = ec2_client.describe_security_groups(Filters=[{'Name': 'group-name', 'Values': [priv_sg_name]}])
priv_sg_id = priv_sg_response['SecurityGroups'][0]['GroupId'] if priv_sg_response['SecurityGroups'] else None

if priv_sg_id is None:
    priv_sg_response = ec2_client.create_security_group(GroupName=priv_sg_name, Description='Private Security Group', VpcId=vpc_id)
    priv_sg_id = priv_sg_response['GroupId']
    ec2_client.authorize_security_group_ingress(GroupId=priv_sg_id, IpPermissions=[
        {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'UserIdGroupPairs': [{'GroupId': bastion_sg_id}]},
        {'IpProtocol': 'icmp', 'FromPort': -1, 'ToPort': -1, 'UserIdGroupPairs': [{'GroupId': bastion_sg_id}]},
        {'IpProtocol': 'tcp', 'FromPort': 3306, 'ToPort': 3306, 'IpRanges': [{'CidrIp': '10.0.0.0/16'}]},
        {'IpProtocol': 'tcp', 'FromPort': 2049, 'ToPort': 2049, 'IpRanges': [{'CidrIp': '10.0.0.0/16'}]},
        {'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443, 'UserIdGroupPairs': [{'GroupId': pub_sg_id}]},
        {'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'UserIdGroupPairs': [{'GroupId': pub_sg_id}]}
    ])
    ec2_client.create_tags(Resources=[priv_sg_id], Tags=[{'Key': 'Name', 'Value': priv_sg_name}])

# --- Check DB Subnet Groups ---
db_subnet_groups = rds_client.describe_db_subnet_groups()
existing_subnet_group_names = {group["DBSubnetGroupName"] for group in db_subnet_groups["DBSubnetGroups"]}

if "mystack-app_db-dbsubnetgroup" not in existing_subnet_group_names:
    rds_client.create_db_subnet_group(
        DBSubnetGroupName="mystack-rds-dbsubnetgroup",
        SubnetIds=[
            "private_subnet1_app_db_id", 
            "private_subnet2_app_db_id",
        ],
        Tags=[{"Key": "Name", "Value": "MYSTACK-RDS-DBSUBNETGROUP"}],
    )

if "mystack-oracle_db-dbsubnetgroup" not in existing_subnet_group_names:
    rds_client.create_db_subnet_group(
        DBSubnetGroupName="mystack-oracle-dbsubnetgroup",
        SubnetIds=[
            "private_subnet1_oracle_db_id",
            "private_subnet2_oracle_db_id",
        ],
        Tags=[{"Key": "Name", "Value": "MYSTACK-ORACLE-DBSUBNETGROUP"}],
    )

if "mystack-java_db-dbsubnetgroup" not in existing_subnet_group_names:
    rds_client.create_db_subnet_group(
        DBSubnetGroupName="mystack-java_db-dbsubnetgroup",
        SubnetIds=[
            "private_subnet1_java_db_id ",
            "private_subnet2_java_db_id ",
        ],
        Tags=[{"Key": "Name", "Value": "MYSTACK-JAVA_DB-DBSUBNETGROUP"}],
    )

# --- Check EFS Setup ---
efs_file_systems = efs_client.describe_file_systems()
existing_efs_names = {fs["CreationToken"] for fs in efs_file_systems["FileSystems"]}

if "CLiXX-EFS" not in existing_efs_names:
    file_system_id = efs_client.create_file_system(
        CreationToken="CLiXX-EFS",
        PerformanceMode="generalPurpose",
        Encrypted=False,
        ThroughputMode="bursting",
        Tags=[{"Key": "Name", "Value": "CLiXX-EFS"}],
    )["FileSystemId"]
else:
    file_system_id = next(fs["FileSystemId"] for fs in efs_file_systems["FileSystems"] if fs["CreationToken"] == "CLiXX-EFS")

# --- Check EFS Mount Targets ---
mount_targets = efs_client.describe_mount_targets(FileSystemId=file_system_id)
existing_mount_targets = {mt["SubnetId"] for mt in mount_targets["MountTargets"]}

if "subnet-priv1-webapp-id" not in existing_mount_targets:
    efs_client.create_mount_target(
        FileSystemId=file_system_id,
        SubnetId="subnet-priv1-webapp-id",
        SecurityGroups=["security-group-id"],
    )

if "subnet-priv2-webapp-id" not in existing_mount_targets:
    efs_client.create_mount_target(
        FileSystemId=file_system_id,
        SubnetId="subnet-priv2-webapp-id",
        SecurityGroups=["security-group-id"],
    )

# --- Check Bastion Instances ---
instances = ec2_resource.describe_instances(Filters=[{"Name": "tag:Name", "Values": ["MYSTACK-BASTION1", "MYSTACK-BASTION2"]}])
existing_instance_ids = {instance["InstanceId"] for reservation in instances["Reservations"] for instance in reservation["Instances"]}

if "MYSTACK-BASTION1" not in existing_instance_ids:
    ec2_client.run_instances(
        ImageId="ami-id",
        InstanceType="t2.micro",
        KeyName="key-pair-name",
        NetworkInterfaces=[{
            "SubnetId": "subnet1-pub-id",
            "AssociatePublicIpAddress": True,
            "Groups": ["bastion-security-group-id"]
        }],
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[{
            "ResourceType": "instance",
            "Tags": [{"Key": "Name", "Value": "MYSTACK-BASTION1"}]
        }]
    )

if "MYSTACK-BASTION2" not in existing_instance_ids:
    ec2_client.run_instances(
        ImageId="ami-id",
        InstanceType="t2.micro",
        KeyName="key-pair-name",
        NetworkInterfaces=[{
            "SubnetId": "subnet2-pub-id",
            "AssociatePublicIpAddress": True,
            "Groups": ["bastion-security-group-id"]
        }],
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[{
            "ResourceType": "instance",
            "Tags": [{"Key": "Name", "Value": "MYSTACK-BASTION2"}]
        }]
    )

# --- Create Target Group ---
# List all target groups and filter for 'CLiXX-TG'
all_tg_response = elbv2_client.describe_target_groups()
target_groups = all_tg_response['TargetGroups']
# Check if 'CLiXX-TG' exists in the list of target groups
target_group_arn = None
for tg in target_groups:
    if tg['TargetGroupName'] == 'CLiXX-TG':
        target_group_arn = tg['TargetGroupArn']
        print(f"Target Group already exists with ARN: {target_group_arn}")
        break
if target_group_arn is None:
    # Target group does not exist, create a new one
    print("Target Group 'CLiXX-TG' not found. Creating a new target group.")
    target_group = elbv2_client.create_target_group(
        Name='CLiXX-TG',
        Protocol='HTTP',
        Port=80,
        VpcId=vpc.id,
        TargetType='instance',
        HealthCheckProtocol='HTTP',
        HealthCheckPort='traffic-port',
        HealthCheckPath='/',
        HealthCheckIntervalSeconds=120,  
        HealthCheckTimeoutSeconds=30,    
        HealthyThresholdCount=5,         
        UnhealthyThresholdCount=4,       
        Matcher={
            'HttpCode': '200-399'        
        }
    )
    target_group_arn = target_group['TargetGroups'][0]['TargetGroupArn']
    print(f"Target Group created with ARN: {target_group_arn}")

# --- Create Application Load Balancer ---
# List all load balancers
all_lb_response = elbv2_client.describe_load_balancers()
load_balancers = all_lb_response['LoadBalancers']
# Check if 'CLiXX-LB' exists in the list of load balancers
load_balancer_arn = None
for lb in load_balancers:
    if lb['LoadBalancerName'] == 'CLiXX-LB':
        load_balancer_arn = lb['LoadBalancerArn']
        print(f"Load Balancer already exists with ARN: {load_balancer_arn}")
        break
if load_balancer_arn is None:
    # Load balancer does not exist, create a new one
    print("Load Balancer 'CLiXX-LB' not found. Creating a new load balancer.")
    load_balancer = elbv2_client.create_load_balancer(
        Name='CLiXX-LB',
        Subnets=[public_subnet1.id, public_subnet2.id],
        SecurityGroups=[pub_sg_id],
        Scheme='internet-facing',
        IpAddressType='ipv4',
        Tags=[
            {
                'Key': 'Name',
                'Value': 'CLiXX-LB'
            },
            {
                'Key': 'Environment',
                'Value': 'dev'
            }
        ]
    )
    load_balancer_arn = load_balancer['LoadBalancers'][0]['LoadBalancerArn']
    print(f"Load Balancer created with ARN: {load_balancer_arn}")

#Create Listener for the Load Balancer (HTTP & HTTPS)
# Retrieve listeners for the load balancer
http_listener_response = elbv2_client.describe_listeners(LoadBalancerArn=load_balancer_arn)
existing_listeners = http_listener_response['Listeners']

# Check if HTTP listener exists
http_listener_exists = any(listener['Protocol'] == 'HTTP' for listener in existing_listeners)
if not http_listener_exists:
    elbv2_client.create_listener(
        LoadBalancerArn=load_balancer_arn,
        Protocol='HTTP',
        Port=80,
        DefaultActions=[{'Type': 'forward', 'TargetGroupArn': target_group_arn}]
    )
    print(f"HTTP Listener created for Load Balancer: {load_balancer_arn}")
else:
    print("HTTP Listener already exists.")

# Check if HTTPS listener exists
https_listener_exists = any(listener['Protocol'] == 'HTTPS' for listener in existing_listeners)
if not https_listener_exists:
    elbv2_client.create_listener(
        LoadBalancerArn=load_balancer_arn,
        Protocol='HTTPS',
        Port=443,
        SslPolicy='ELBSecurityPolicy-2016-08',
        Certificates=[{
            'CertificateArn': certificate_arn
        }],
        DefaultActions=[{'Type': 'forward', 'TargetGroupArn': target_group_arn}]
    )
    print(f"HTTPS Listener created for Load Balancer: {load_balancer_arn}")
else:
    print("HTTPS Listener already exists.")

# --- RDS Instance ---
DBSubnetGroupName="mystack-rds-dbsubnetgroup"
# Check if the DB instance already exists
db_instances = rds_client.describe_db_instances()
db_instance_identifiers = [db['DBInstanceIdentifier'] for db in db_instances['DBInstances']]
if db_instance_identifier in db_instance_identifiers:
    # If the instance exists, print the details and skip restore
    instances = rds_client.describe_db_instances(DBInstanceIdentifier=db_instance_identifier)
    print(f"DB Instance '{db_instance_identifier}' already exists. Details: {instances}")
else:
    # Restore the DB instance from snapshot if it doesn't exist
    print(f"DB Instance '{db_instance_identifier}' not found. Restoring from snapshot...")
    # Attempt to restore the DB from the snapshot
    response = rds_client.restore_db_instance_from_db_snapshot(
        DBInstanceIdentifier=db_instance_identifier,
        DBSnapshotIdentifier=db_snapshot_identifier,
        DBInstanceClass=db_instance_class,
        VpcSecurityGroupIds=[private_subnet1_app_db.id],
        DBSubnetGroupName=DBSubnetGroupName,
        PubliclyAccessible=False,
        MultiAZ=True,
        SkipFinalSnapshot=True,
        Tags=[{'Key': 'Name', 'Value': 'wordpressdbclixx'}]
    )
    print(f"Restore operation initiated. Response: {response}")


# --- Create Route 53 record for the load balancer ---
route53_response = route53_client.list_resource_record_sets(
    HostedZoneId=hosted_zone_id
)
# Check if the record already exists using a broader approach
record_exists = any(record['Name'] == record_name for record in route53_response['ResourceRecordSets'])
if not record_exists:
    route53_client.change_resource_record_sets(
        HostedZoneId=hosted_zone_id,
        ChangeBatch={
            'Comment': 'Create a record for the CLiXX Load Balancer',
            'Changes': [{
                'Action': 'CREATE',
                'ResourceRecordSet': {
                    'Name': record_name,
                    'Type': 'A',
                    'AliasTarget': {
                        'HostedZoneId': load_balancer['LoadBalancers'][0]['CanonicalHostedZoneId'],
                        'DNSName': load_balancer['LoadBalancers'][0]['DNSName'],
                        'EvaluateTargetHealth': False
                    }
                }
            }]
        }
    )
    print(f"Route 53 record created for {record_name}")
else:
    print(f"Route 53 record already exists for {record_name}")

# Define user_data_script with dynamic variables
efs_name = "CLiXX-EFS"
mount_point = "/var/www/html"
user_data_script = f'''#!/bin/bash
# Switch to root user
sudo su -

# Update packages and install necessary utilities
yum update -y
yum install -y nfs-utils aws-cli

# Fetch the session token and region information for metadata
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
AVAILABILITY_ZONE=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/meta-data/placement/availability-zone")
REGION=${{AVAILABILITY_ZONE:0:-1}}

# Ensure DNS resolution and DNS hostnames are enabled (for VPC)
echo "nameserver 169.254.169.253" >> /etc/resolv.conf

# Use the passed in file_system_id
file_system_id="{file_system_id}"
if [ -z "$file_system_id" ]; then
    echo "Error: FileSystemId not provided"
    exit 1
fi

# Install the NFS utilities for mounting EFS
yum install -y nfs-utils

# Wait until the EFS file system is available
while true; do
    status=$(aws efs describe-file-systems --file-system-id $file_system_id --query "FileSystems[0].LifeCycleState" --output text --region $REGION)
    if [ "$status" == "available" ]; then
        echo "EFS FileSystem is available."
        break
    else
        echo "Waiting for EFS FileSystem to become available. Retrying in 10 seconds..."
    fi
    sleep 10
done

# Ensure the mount target exists in the same availability zone as the EC2 instance
while true; do
    mount_target=$(aws efs describe-mount-targets --file-system-id $file_system_id --region $REGION --query 'MountTargets[?AvailabilityZoneName==`'$AVAILABILITY_ZONE'`].MountTargetId' --output text)
    if [ -n "$mount_target" ]; then
        echo "Mount target found in availability zone $AVAILABILITY_ZONE."
        break
    else
        echo "Waiting for mount target in availability zone $AVAILABILITY_ZONE. Retrying in 10 seconds..."
    fi
    sleep 10
done

# Restart network service to ensure DNS resolution
sudo service network restart

# Create mount point and set permissions
MOUNT_POINT={mount_point}
mkdir -p $MOUNT_POINT
chown ec2-user:ec2-user $MOUNT_POINT

# Add EFS to fstab and attempt to mount
echo "${{file_system_id}}.efs.${{REGION}}.amazonaws.com:/ $MOUNT_POINT nfs4 defaults,_netdev 0 0" >> /etc/fstab

sleep 180
# Attempt to mount, retrying if it fails
attempt=0
max_attempts=5
while (( attempt < max_attempts )); do
    mount -a -t nfs4 && echo "EFS mounted successfully." && break
    echo "Mount failed, retrying after network restart..."
    sudo service network restart
    sleep 10
    attempt=$((attempt + 1))
done

# Check if mount was successful
if ! mount | grep -q $MOUNT_POINT; then
    echo "Error: EFS mount failed after $max_attempts attempts. Continuing with the rest of the script."
else
    echo "EFS successfully mounted at $MOUNT_POINT."
fi

chmod -R 755 $MOUNT_POINT

# Switch back to ec2-user
sudo su - ec2-user

# Proceed with the rest of the CLiXX setup
# Variables for WordPress Setup
CLiXX_GIT_REPO_URL="https://github.com/stackitgit/CliXX_Retail_Repository.git"
WordPress_DB_NAME="wordpressdb"
WordPress_DB_USER="wordpressuser"
WordPress_DB_PASS="W3lcome123"
WordPress_DB_HOST="wordpressdbclixx.cj0yi4ywm61r.us-east-1.rds.amazonaws.com"
RECORD_NAME="{record_name}"
WP_CONFIG_PATH="/var/www/html/wp-config.php"

# Install the needed packages and enable the services
sudo yum update -y
sudo yum install git -y
sudo amazon-linux-extras install -y lamp-mariadb10.2-php7.2 php7.2
sudo yum install -y httpd mariadb-server
sudo systemctl start httpd
sudo systemctl enable httpd
sudo systemctl is-enabled httpd

# Add ec2-user to Apache group and grant permissions to /var/www
sudo usermod -a -G apache ec2-user
sudo chown -R ec2-user:apache /var/www
sudo chmod 2775 /var/www && find /var/www -type d -exec sudo chmod 2775 {{}} \;
find /var/www -type f -exec sudo chmod 0664 {{}} \;

# Check if wp-config.php exists before cloning the repository
if [ ! -f "/var/www/html/wp-config.php" ]; 
then
    echo "Cloning CliXX Retail repository..."
    git clone $CLiXX_GIT_REPO_URL /var/www/html
else
    echo "WordPress already installed, skipping clone..."
fi

# Configure the wp-config.php file
sudo cp /var/www/html/wp-config-sample.php /var/www/html/wp-config.php
sudo sed -i "s/database_name_here/$WordPress_DB_NAME/" $WP_CONFIG_PATH
sudo sed -i "s/username_here/$WordPress_DB_USER/" $WP_CONFIG_PATH
sudo sed -i "s/password_here/$WordPress_DB_PASS/" $WP_CONFIG_PATH
sudo sed -i "s/localhost/$WordPress_DB_HOST/" $WP_CONFIG_PATH

# Add HTTPS enforcement to wp-config.php
sudo sed -i "81i if (isset(\$_SERVER['HTTP_X_FORWARDED_PROTO']) && \$_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {{ \$_SERVER['HTTPS'] = 'on'; }}" $WP_CONFIG_PATH

# Allow WordPress to use Permalinks
sudo sed -i '151s/None/All/' /etc/httpd/conf/httpd.conf

# Grant file ownership of /var/www to apache user
sudo chown -R apache /var/www
sudo chgrp -R apache /var/www
sudo chmod 2775 /var/www
find /var/www -type d -exec sudo chmod 2775 {{}} \;
sudo find /var/www -type f -exec sudo chmod 0664 {{}} \;

# Restart Apache
sudo systemctl restart httpd
sudo service httpd restart
sudo systemctl enable httpd

# Wait for the database to be up
until mysqladmin ping -h $WordPress_DB_HOST -u $WordPress_DB_USER -p$WordPress_DB_PASS --silent; do
    echo "Waiting for database to be available..."
    sleep 10
done

# Check and update WordPress options
existing_value=$(mysql -u ${{WordPress_DB_USER}} -p${{WordPress_DB_PASS}} -h ${{WordPress_DB_HOST}} -D ${{WordPress_DB_NAME}} -sse "SELECT COUNT(*) FROM wp_options WHERE (option_name = 'home' OR option_name = 'siteurl' OR option_name = 'ping_sites' OR option_name = 'open_shop_header_retina_logo') AND option_value = '${{RECORD_NAME}}';")

if [ "$existing_value" -eq 4 ]; 
then
    echo "All relevant options are already set to ${{RECORD_NAME}}. No update needed."
else
    echo "Updating the options with the new record name value."
    mysql -u ${{WordPress_DB_USER}} -p${{WordPress_DB_PASS}} -h ${{WordPress_DB_HOST}} -D ${{WordPress_DB_NAME}} <<EOF
    UPDATE wp_options SET option_value = "https://${{RECORD_NAME}}" WHERE option_name = "home";
    UPDATE wp_options SET option_value = "https://${{RECORD_NAME}}" WHERE option_name = "siteurl";
    UPDATE wp_options SET option_value = "https://${{RECORD_NAME}}" WHERE option_name = "ping_sites";
    UPDATE wp_options SET option_value = "https://${{RECORD_NAME}}" WHERE option_name = "open_shop_header_retina_logo";
EOF
    echo "Update queries executed successfully."
fi

'''

# Encode the user data to Base64
user_data_base64 = base64.b64encode(user_data_script.encode('utf-8')).decode('utf-8')

# --- Create Launch Template ---
#List all launch templates and check for 'CLiXX-LT'
all_lt_response = ec2_client.describe_launch_templates()
launch_template_names = [lt['LaunchTemplateName'] for lt in all_lt_response['LaunchTemplates']]

if 'CLiXX-LT' in launch_template_names:
    # Get the ID of the existing launch template
    launch_template_id = next(lt['LaunchTemplateId'] for lt in all_lt_response['LaunchTemplates'] if lt['LaunchTemplateName'] == 'CLiXX-LT')
    print(f"Launch Template already exists with ID: {launch_template_id}")
else:
    # Create a new launch template since it doesn't exist
    launch_template = ec2_client.create_launch_template(
        LaunchTemplateName='CLiXX-LT',
        VersionDescription='Version 1',
        LaunchTemplateData={
            'ImageId': ami_id,  
            'InstanceType': instance_type,  
            'KeyName': key_pair_name,  
            #'SecurityGroupIds': [public_sg.id],  
            'UserData': user_data_base64,  
            'IamInstanceProfile': {
                'Name': 'EFS_operations'  
            },
            'NetworkInterfaces': [{
                'AssociatePublicIpAddress': True,
                'DeviceIndex': 0,
                'SubnetId': private_subnet1_webapp_id,
                'Groups': [priv_sg_id]
            }]
        }
    )
    launch_template_id = launch_template['LaunchTemplate']['LaunchTemplateId']
    print(f"Launch Template created with ID: {launch_template_id}")

# --- Create Auto Scaling Group ---
# List all Auto Scaling Groups and check for 'CLiXX-ASG'
all_asg_response = autoscaling_client.describe_auto_scaling_groups()
asg_names = [asg['AutoScalingGroupName'] for asg in all_asg_response['AutoScalingGroups']]
if 'CLiXX-ASG' in asg_names:
    print("Auto Scaling Group already exists.")
else:
    # Create a new Auto Scaling Group since it doesn't exist
    autoscaling_client.create_auto_scaling_group(
        AutoScalingGroupName='CLiXX-ASG',
        LaunchTemplate={
            'LaunchTemplateId': launch_template_id, 
            'Version': '1'
        },
        MinSize=1,
        MaxSize=3,
        DesiredCapacity=1,
        VPCZoneIdentifier=[private_subnet1_webapp_id,private_subnet2_webapp_id],
        TargetGroupARNs=[target_group_arn], 
        Tags=[
            {
                'Key': 'Name',
                'Value': 'CLiXX',
                'PropagateAtLaunch': True
            }
        ]
    )
    print("Auto Scaling Group created successfully.")

