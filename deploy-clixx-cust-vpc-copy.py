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

# Define Variables
ami_id = 'ami-00f251754ac5da7f0'
key_pair_name = 'stack_devops_kp'
instance_type = 't2.micro'
db_instance_identifier = 'wordpressdbclixx'
db_snapshot_identifier = 'arn:aws:rds:us-east-1:577701061234:snapshot:wordpressdbclixx-ecs-snapshot'
db_instance_class = 'db.m6gd.large'
efs_name = 'CLiXX-EFS'
hosted_zone_id = 'Z04517273VCLIDX9UEQR7'
record_name = 'test.clixx-della.com'

# Step 1: Create a VPC
vpc = ec2_resource.create_vpc(
    CidrBlock='10.0.0.0/16',
    TagSpecifications=[{'ResourceType': 'vpc', 'Tags': [{'Key': 'Name', 'Value': 'TESTSTACKVPC'}]}]
)
vpc.wait_until_available()

# Enable DNS support and hostnames for the VPC
vpc.modify_attribute(EnableDnsSupport={'Value': True})
vpc.modify_attribute(EnableDnsHostnames={'Value': True})
print(f"Created VPC with ID: {vpc.id}")

# Step 2: Create Internet Gateway and Attach to VPC
igw = ec2_resource.create_internet_gateway(
    TagSpecifications=[{'ResourceType': 'internet-gateway', 'Tags': [{'Key': 'Name', 'Value': 'TESTSTACKIGW'}]}]
)
vpc.attach_internet_gateway(InternetGatewayId=igw.id)
print(f"Internet Gateway attached to VPC")

# Step 3: Create Public Subnets
availability_zones = ['us-east-1a', 'us-east-1b']

pub_subnet1 = ec2_resource.create_subnet(
    CidrBlock='10.0.1.0/24',
    VpcId=vpc.id,
    AvailabilityZone=availability_zones[0],
    TagSpecifications=[{'ResourceType': 'subnet', 'Tags': [{'Key': 'Name', 'Value': 'TESTSTACKPUBSUB1'}]}]
)

pub_subnet2 = ec2_resource.create_subnet(
    CidrBlock='10.0.2.0/24',
    VpcId=vpc.id,
    AvailabilityZone=availability_zones[1],
    TagSpecifications=[{'ResourceType': 'subnet', 'Tags': [{'Key': 'Name', 'Value': 'TESTSTACKPUBSUB2'}]}]
)
print(f"Public Subnets created in Availability Zones {availability_zones}")

# Step 4: Create Private Subnets
priv_subnet1 = ec2_resource.create_subnet(
    CidrBlock='10.0.3.0/24',
    VpcId=vpc.id,
    AvailabilityZone=availability_zones[0],
    TagSpecifications=[{'ResourceType': 'subnet', 'Tags': [{'Key': 'Name', 'Value': 'TESTSTACKPRIVSUB1'}]}]
)

priv_subnet2 = ec2_resource.create_subnet(
    CidrBlock='10.0.4.0/24',
    VpcId=vpc.id,
    AvailabilityZone=availability_zones[1],
    TagSpecifications=[{'ResourceType': 'subnet', 'Tags': [{'Key': 'Name', 'Value': 'TESTSTACKPRIVSUB2'}]}]
)
print(f"Private Subnets created in Availability Zones {availability_zones}")

# Step 5: Create Route Tables and associate with subnets
pub_route_table = ec2_resource.create_route_table(
    VpcId=vpc.id,
    TagSpecifications=[{'ResourceType': 'route-table', 'Tags': [{'Key': 'Name', 'Value': 'TESTSTACKPUBRT'}]}]
)

priv_route_table = ec2_resource.create_route_table(
    VpcId=vpc.id,
    TagSpecifications=[{'ResourceType': 'route-table', 'Tags': [{'Key': 'Name', 'Value': 'TESTSTACKPRIVRT'}]}]
)

# Create route for Internet access for public subnets
pub_route_table.create_route(
    DestinationCidrBlock='0.0.0.0/0',
    GatewayId=igw.id
)

# Associate public subnets with the public route table
pub_route_table.associate_with_subnet(SubnetId=pub_subnet1.id)
pub_route_table.associate_with_subnet(SubnetId=pub_subnet2.id)

# Associate private subnets with the private route table
priv_route_table.associate_with_subnet(SubnetId=priv_subnet1.id)
priv_route_table.associate_with_subnet(SubnetId=priv_subnet2.id)

print(f"Route tables created and associated with subnets.")

# Step 6: Create Security Groups
public_sg = ec2_resource.create_security_group(
    GroupName='TESTSTACKSG',
    Description='Public Security Group for App Servers',
    VpcId=vpc.id
)
public_sg.authorize_ingress(IpPermissions=[
    {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},  # SSH
    {'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},  # HTTP
    {'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},  # HTTPS
])

private_sg = ec2_resource.create_security_group(
    GroupName='TESTSTACKSGPRIV',
    Description='Private Security Group for RDS and EFS',
    VpcId=vpc.id
)
private_sg.authorize_ingress(IpPermissions=[
    {'IpProtocol': 'tcp', 'FromPort': 2049, 'ToPort': 2049, 'IpRanges': [{'CidrIp': '10.0.0.0/16'}]},  # NFS (EFS)
    {'IpProtocol': 'tcp', 'FromPort': 3306, 'ToPort': 3306, 'IpRanges': [{'CidrIp': '10.0.0.0/16'}]},  # MySQL (RDS)
])
print(f"Security groups created: Public SG (ID: {public_sg.id}), Private SG (ID: {private_sg.id})")

# Create DB Subnet Group
# Create or handle existing DB Subnet Group
DBSubnetGroupName = 'mystack-db-subnet-group'
try:
    response = rds_client.create_db_subnet_group(
        DBSubnetGroupName=DBSubnetGroupName,
        SubnetIds=[priv_subnet1.id, priv_subnet2.id],
        DBSubnetGroupDescription='My stack DB subnet group',
        Tags=[{'Key': 'Name', 'Value': 'MYSTACKDBSUBNETGROUP'}]
    )
    DBSubnetGroupName = response['DBSubnetGroup']['DBSubnetGroupName']
    print(f"DB Subnet Group '{DBSubnetGroupName}' created successfully.")

except rds_client.exceptions.DBSubnetGroupAlreadyExistsFault:
    print(f"DB Subnet Group '{DBSubnetGroupName}' already exists. Proceeding with the existing one.")
    response = rds_client.describe_db_subnet_groups(
        DBSubnetGroupName=DBSubnetGroupName
    )
    # Check if the response contains the expected keys
    if 'DBSubnetGroups' in response and len(response['DBSubnetGroups']) > 0:
        DBSubnetGroupName = response['DBSubnetGroups'][0].get('DBSubnetGroupName', 'Unknown')
        print(f"Using existing DB Subnet Group: '{DBSubnetGroupName}'")
    else:
        print("No DB Subnet Groups found in the response.")

except Exception as e:
    print(f"An error occurred: {str(e)}")

# Step 7: Restore DB Instance from Snapshot
try:
    rds_client.restore_db_instance_from_db_snapshot(
        DBInstanceIdentifier=db_instance_identifier,
        DBSnapshotIdentifier=db_snapshot_identifier,
        DBInstanceClass=db_instance_class,
        VpcSecurityGroupIds=[private_sg.id],
        AvailabilityZone='us-east-1a',
        MultiAZ=False,
        PubliclyAccessible=False,
        DBSubnetGroupName=DBSubnetGroupName
    )
    print(f"Restored DB instance '{db_instance_identifier}' from snapshot.")
except Exception as e:
    print(f"An error occurred while restoring the DB instance: {str(e)}")

# Step 8: Create EFS file system
# Check if EFS with creation token exists
efs_response = efs_client.describe_file_systems(
    CreationToken='CLiXX-EFS'
)

# If it exists, proceed with the existing EFS
if efs_response['FileSystems']:
    file_system_id = efs_response['FileSystems'][0]['FileSystemId']
else:
    # Create EFS
    efs_response = efs_client.create_file_system(
        CreationToken='CLiXX-EFS',
        PerformanceMode='generalPurpose'
    )
    file_system_id = efs_response['FileSystemId']

# Wait until the EFS file system is in 'available' state
while True:
    efs_info = efs_client.describe_file_systems(
        FileSystemId=file_system_id
    )
    lifecycle_state = efs_info['FileSystems'][0]['LifeCycleState']
    if lifecycle_state == 'available':
        print(f"EFS {efs_name} is now available with FileSystemId: {file_system_id}")
        break
    else:
        print(f"EFS is in '{lifecycle_state}' state. Waiting for it to become available...")
        time.sleep(10)

# After ensuring the file system is available, create the mount targets in the private subnets
private_subnet_ids = [priv_subnet1.id, priv_subnet2.id] 
for private_subnet_id in private_subnet_ids:
    mount_target_response = efs_client.create_mount_target(
        FileSystemId=file_system_id,
        SubnetId=private_subnet_id,
        SecurityGroups=[private_sg.id]
    )
    print(f"Mount target created in Private Subnet: {private_subnet_id}")
# Attach Lifecycle Policy (optional)
efs_client.put_lifecycle_configuration(
    FileSystemId=file_system_id,
    LifecyclePolicies=[
        {
            'TransitionToIA': 'AFTER_30_DAYS'  # Archive files after 30 days
        },
        {
            'TransitionToPrimaryStorageClass': 'AFTER_1_ACCESS'  # Move back on first access
        }
    ]
)
print(f"Lifecycle policy applied to EFS {efs_name}")

# Step 9: Create Target Group
target_group = elbv2_client.create_target_group(
    Name='CLiXX-TG',
    Protocol='HTTP',
    Port=80,
    VpcId=vpc.id,
    TargetType='instance'
)
target_group_arn = target_group['TargetGroups'][0]['TargetGroupArn']

# Step 10: Create Application Load Balancer
load_balancer = elbv2_client.create_load_balancer(
    Name='CLiXX-LB',
    Subnets=[pub_subnet1.id, pub_subnet2.id],
    SecurityGroups=[public_sg.id],
    Scheme='internet-facing',
    Type='application',
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

# Step 11: Create Listener for the Load Balancer (HTTP & HTTPS)
# HTTP Listener
elbv2_client.create_listener(
    LoadBalancerArn=load_balancer_arn,
    Protocol='HTTP',
    Port=80,
    DefaultActions=[
        {
            'Type': 'forward',
            'TargetGroupArn': target_group_arn
        }
    ]
)
# HTTPS Listener
elbv2_client.create_listener(
    LoadBalancerArn=load_balancer_arn,
    Protocol='HTTPS',
    Port=443,
    SslPolicy='ELBSecurityPolicy-2016-08',
    Certificates=[
        {
            'CertificateArn': 'arn:aws:acm:us-east-1:043309319757:certificate/13c75e7c-517a-4a5e-b27c-b2fce2f442e1'
        }
    ],
    DefaultActions=[
        {
            'Type': 'forward',
            'TargetGroupArn': target_group_arn
        }
    ]
)

# Step 12: Create Route 53 record for the load balancer
route53_client.change_resource_record_sets(
    HostedZoneId=hosted_zone_id,
    ChangeBatch={
        'Comment': 'Create a record for the CLixx Load Balancer',
        'Changes': [
            {
                'Action': 'CREATE',
                'ResourceRecordSet': {
                    'Name': record_name,
                    'Type': 'A',
                    'AliasTarget': {
                        'HostedZoneId': 'Z35SXDOTRQ7X7K',
                        'DNSName': load_balancer['LoadBalancers'][0]['DNSName'],
                        'EvaluateTargetHealth': False
                    }
                }
            }
        ]
    }
)

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

# Step 13: Create Launch Template
launch_template = ec2_client.create_launch_template(
    LaunchTemplateName='CLiXX-LT',
    VersionDescription='Version 1',
    LaunchTemplateData={
        'ImageId': ami_id,
        'InstanceType': instance_type,
        'KeyName': key_pair_name,
        'SecurityGroupIds': [public_sg.id],
        'UserData': user_data_base64,
        'IamInstanceProfile': {
            'Name': 'EFS_operations'  # Replace with your IAM role name
        }
    }
)
launch_template_id = launch_template['LaunchTemplate']['LaunchTemplateId']

# Step 14: Create Auto Scaling Group (last step)
autoscaling_client.create_auto_scaling_group(
    AutoScalingGroupName='CLiXX-ASG',
    LaunchTemplate={
        'LaunchTemplateId': launch_template_id,
        'Version': '1'
    },
    MinSize=1,
    MaxSize=3,
    DesiredCapacity=1,
    VPCZoneIdentifier=f'{pub_subnet1.id},{pub_subnet2.id}',
    TargetGroupARNs=[target_group_arn],
    Tags=[
        {
        'Key': 'Name',
        'Value': 'CLiXX',
        'PropagateAtLaunch': True
        }
    ]
)