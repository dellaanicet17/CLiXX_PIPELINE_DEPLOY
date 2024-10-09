#!/usr/bin/env python3
import boto3, botocore

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

# Define variables
aws_region = "us-east-1"
vpc_id = 'vpc-0785754acd9374fb6'
subnet_id = 'subnet-0e9f4974af6be42ae'
subnet_id2 = 'subnet-0ff64f61153db745d'
ami_id = 'ami-00f251754ac5da7f0'
key_pair_name = 'stack_devops_kp'
instance_type = 't2.micro'
db_instance_identifier = 'wordpressdbclixx'
db_snapshot_identifier = 'arn:aws:rds:us-east-1:577701061234:snapshot:wordpressdbclixx-ecs-snapshot'
db_instance_class = 'db.m6gd.large'
availability_zone = 'us-east-1a'
hosted_zone_id = 'Z04517273VCLIDX9UEQR7'
record_name = 'test.clixx-della.com'

# Step 1: Create EFS file system
efs_response = efs_client.create_file_system(
    CreationToken='CLiXX-EFS',
    PerformanceMode='generalPurpose',
    Encrypted=False,
    Tags=[
        {'Key': 'Name', 'Value': 'CLiXX-EFS'}
    ]
)
file_system_id = efs_response['FileSystemId']

# Step 2: Create Security group
security_group = ec2_resource.create_security_group(
    Description='Allow inbound traffic for various services',
    GroupName='Test1_Stack_Web_DMZ',
    VpcId=vpc_id,
    TagSpecifications=[
        {
            'ResourceType': 'security-group',
            'Tags': [
                {
                    'Key': 'Name', 
                    'Value': 'Test1_Stack_Web_DMZ'
                },
            ]
        },
    ]
)
# Store the security group ID in a variable
security_group_id = security_group.id

# Authorize inbound rules (SSH, HTTP, HTTPS, MySQL/Aurora, NFS)
inbound_rules = [
    {'CidrIp': '0.0.0.0/0', 'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22},    # SSH
    {'CidrIp': '0.0.0.0/0', 'IpProtocol': 'tcp', 'FromPort': 80, 'ToPort': 80},    # HTTP
    {'CidrIp': '0.0.0.0/0', 'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443},  # HTTPS
    {'CidrIp': '0.0.0.0/0', 'IpProtocol': 'tcp', 'FromPort': 3306, 'ToPort': 3306},# MySQL/Aurora
    {'CidrIp': '0.0.0.0/0', 'IpProtocol': 'tcp', 'FromPort': 2049, 'ToPort': 2049} # NFS
]
for rule in inbound_rules:
        security_group.authorize_ingress(
        CidrIp=rule['CidrIp'],
        IpProtocol=rule['IpProtocol'],
        FromPort=rule['FromPort'],
        ToPort=rule['ToPort']
    )
# Print the created security group ID
print(f"Security Group {security_group_id} with inbound rules for SSH, HTTP, HTTPS, NFS, MySQL/Aurora has been created.")

# Step 3: Restore DB Instance from Snapshot
rds_client.restore_db_instance_from_db_snapshot(
    DBInstanceIdentifier=db_instance_identifier,
    DBSnapshotIdentifier=db_snapshot_identifier,
    DBInstanceClass=db_instance_class,
    VpcSecurityGroupIds=[security_group_id],
    AvailabilityZone=availability_zone,
    MultiAZ=False,
    PubliclyAccessible=True
)

# Step 4: Create Target Group
target_group = elbv2_client.create_target_group(
    Name='CLiXX-TG',
    Protocol='HTTP',
    Port=80,
    VpcId=vpc_id,
    TargetType='instance'
)
target_group_arn = target_group['TargetGroups'][0]['TargetGroupArn']

# Step 5: Create Application Load Balancer
load_balancer = elbv2_client.create_load_balancer(
    Name='CLiXX-LB',
    Subnets=[subnet_id, subnet_id2],
    SecurityGroups=[security_group_id],
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

# Step 6: Create Listener for the Load Balancer (HTTP & HTTPS)
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

# HTTPS Listener (You will need an SSL certificate from ACM for this)
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

# Step 7: Create Route 53 record for the load balancer
route53_client.change_resource_record_sets(
    HostedZoneId=hosted_zone_id,
    ChangeBatch={
        'Comment': 'Create a record for the WordPress Load Balancer',
        'Changes': [
            {
                'Action': 'CREATE',
                'ResourceRecordSet': {
                    'Name': record_name,
                    'Type': 'A',
                    'AliasTarget': {
                        'HostedZoneId': 'Z04517273VCLIDX9UEQR7',  # Hosted zone ID for ALB in us-east-1
                        'DNSName': load_balancer['LoadBalancers'][0]['DNSName'],
                        'EvaluateTargetHealth': False
                    }
                }
            }
        ]
    }
)

# Define user_data_script with dynamic variables
user_data_script = f'''#!/bin/bash

# Switch to root user
sudo su -

# Update packages and install necessary utilities
yum update -y
yum install -y nfs-utils 

# Fetch the session token and region information for metadata
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
AVAILABILITY_ZONE=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/meta-data/placement/availability-zone")
REGION=${{AVAILABILITY_ZONE:0:-1}}

# Set variables
MOUNT_POINT=/var/www/html

# Create and set permissions for the mount point
mkdir -p ${{MOUNT_POINT}}
chown ec2-user:ec2-user ${{MOUNT_POINT}}

# Mount the EFS file system
echo "{file_system_id}.efs.${{REGION}}.amazonaws.com:/ ${{MOUNT_POINT}} nfs4 nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,_netdev 0 0" >> /etc/fstab
mount -a -t nfs4
chmod -R 755 /var/www/html

# Switch back to ec2-user
sudo su - ec2-user

# Variables - Update these as needed
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

# Check and update WordPress options
existing_value=$(mysql -u ${{WordPress_DB_USER}} -p${{WordPress_DB_PASS}} -h ${{WordPress_DB_HOST}} -D ${{WordPress_DB_NAME}} -sse "SELECT COUNT(*) FROM wp_options WHERE (option_name = 'home' OR option_name = 'siteurl' OR option_name = 'ping_sites' OR option_name = 'open_shop_header_retina_logo') AND option_value = '${{RECORD_NAME}}';")

if [ "$existing_value" -eq 4 ]; 
then
    echo "All relevant options are already set to ${{RECORD_NAME}}. No update needed."
else
    echo "Updating the options with the new record name value."
    mysql -u ${{WordPress_DB_USER}} -p${{WordPress_DB_PASS}} -h ${{WordPress_DB_HOST}} -D ${{WordPress_DB_NAME}} <<EOF
    UPDATE wp_options SET option_value = "${{RECORD_NAME}}" WHERE option_name = "home";
    UPDATE wp_options SET option_value = "${{RECORD_NAME}}" WHERE option_name = "siteurl";
    UPDATE wp_options SET option_value = "${{RECORD_NAME}}" WHERE option_name = "ping_sites";
    UPDATE wp_options SET option_value = "${{RECORD_NAME}}" WHERE option_name = "open_shop_header_retina_logo";
EOF
    echo "Update queries executed successfully."
fi
'''

# Step 8: Create Launch Template
launch_template = ec2_client.create_launch_template(
    LaunchTemplateName='CLiXX-LT',
    VersionDescription='Version 1',
    LaunchTemplateData={
        'ImageId': ami_id,
        'InstanceType': instance_type,
        'KeyName': key_pair_name,
        'SecurityGroupIds': [security_group_id],
        'UserData': user_data_script
    }
)
launch_template_id = launch_template['LaunchTemplate']['LaunchTemplateId']

# Step 9: Create Auto Scaling Group (last step)
autoscaling_client.create_auto_scaling_group(
    AutoScalingGroupName='CLiXX-ASG',
    LaunchTemplate={
        'LaunchTemplateId': launch_template_id,
        'Version': '1'
    },
    MinSize=1,
    MaxSize=3,
    DesiredCapacity=1,
    VPCZoneIdentifier=subnet_id,
    TargetGroupARNs=[target_group_arn],
    Tags=[
        {
            'Key': 'Name',
            'Value': 'CLiXX'
        }
    ]
)