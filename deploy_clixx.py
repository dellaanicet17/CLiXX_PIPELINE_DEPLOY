#!/usr/bin/env python3
import boto3, botocore

# Assume role to get temporary credentials
sts_client = boto3.client('sts')
assumed_role_object = sts_client.assume_role(
    RoleArn='arn:aws:iam::043309319757:role/Engineer', 
    RoleSessionName='mysession'
)
credentials = assumed_role_object['Credentials']

# Variables
aws_region = "us-east-1"
vpc_id = 'vpc-0785754acd9374fb6'

# Create EC2 resource with assumed role credentials
ec2_resource = boto3.resource(
    'ec2',
    region_name=aws_region,
    aws_access_key_id=credentials['AccessKeyId'],
    aws_secret_access_key=credentials['SecretAccessKey'],
    aws_session_token=credentials['SessionToken']
)

# Create the security group
security_group = ec2_resource.create_security_group(
    Description='Allow inbound traffic for various services',
    GroupName='Test_Stack_Web_DMZ',
    VpcId=vpc_id,
    TagSpecifications=[
        {
            'ResourceType': 'security-group',
            'Tags': [
                {'Key': 'Name', 'Value': 'Test_Stack_Web_DMZ'}
            ]
        },
    ],
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

#########################################################################################################################

# Variables
db_instance_identifier = 'wordpressdbclixx'
db_snapshot_identifier = 'arn:aws:rds:us-east-1:577701061234:snapshot:wordpressdbclixx-ecs-snapshot'
db_instance_class = 'db.m6gd.large'  # Example instance class
availabilityzone = 'us-east-1a'
#security_group_id = 'sg-024f0157b123d6a8c'

# Create RDS client
rds_client=boto3.client('rds',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'])

# Restore DB instance from snapshot
response = rds_client.restore_db_instance_from_db_snapshot(
    DBInstanceIdentifier=db_instance_identifier,
    DBSnapshotIdentifier=db_snapshot_identifier,
    DBInstanceClass=db_instance_class,
    VpcSecurityGroupIds=[security_group_id],
    AvailabilityZone=availabilityzone,
    MultiAZ=False,
    PubliclyAccessible=True
)

#########################################################################################################################

# Variables
aws_region = "us-east-1"
key_pair_name = 'stack_devops_kp'
ami_id = 'ami-00f251754ac5da7f0' # Amazon Linux 2
subnet_id = 'subnet-0e9f4974af6be42ae' 
#security_group_id = 'sg-024f0157b123d6a8c'
user_data = '''#!/bin/bash -xe
# Variables - Update these as needed
CLiXX_GIT_REPO_URL="https://github.com/stackitgit/CliXX_Retail_Repository.git"
WordPress_DB_NAME="wordpressdb" 
WordPress_DB_USER="wordpressuser"
WordPress_DB_PASS="W3lcome123" 
WordPress_DB_HOST="wordpressdbclixx.cj0yi4ywm61r.us-east-1.rds.amazonaws.com" 

##Install the needed packages and enable the services(MariaDb, Apache)
sudo yum update -y
sudo yum install git -y
sudo amazon-linux-extras install -y lamp-mariadb10.2-php7.2 php7.2
sudo yum install -y httpd mariadb-server
sudo systemctl start httpd
sudo systemctl enable httpd
sudo systemctl is-enabled httpd
 
## Add ec2-user to Apache group and grant permissions to /var/www
sudo usermod -a -G apache ec2-user
sudo chown -R ec2-user:apache /var/www
sudo chmod 2775 /var/www && find /var/www -type d -exec sudo chmod 2775 {} \;
find /var/www -type f -exec sudo chmod 0664 {} \;
cd /var/www/html
 
# Clone the WordPress application code from the Git repository
git clone $CLiXX_GIT_REPO_URL /var/www/html 
#cp -r CliXX_Retail_Repository/* /var/www/html

# Configure the wp-config.php file
sudo cp /var/www/html/wp-config-sample.php /var/www/html/wp-config.php

sudo sed -i "s/database_name_here/$WordPress_DB_NAME/" /var/www/html/wp-config.php
sudo sed -i "s/username_here/$WordPress_DB_USER/" /var/www/html/wp-config.php
sudo sed -i "s/password_here/$WordPress_DB_PASS/" /var/www/html/wp-config.php
sudo sed -i "s/localhost/$WordPress_DB_HOST/" /var/www/html/wp-config.php
 
## Allow wordpress to use Permalinks
sudo sed -i '151s/None/All/' /etc/httpd/conf/httpd.conf
 
## Grant file ownership of /var/www & its contents to apache user
sudo chown -R apache /var/www
## Grant group ownership of /var/www & contents to apache group
sudo chgrp -R apache /var/www
##Change directory permissions of /var/www & its subdir to add group write 
sudo chmod 2775 /var/www
find /var/www -type d -exec sudo chmod 2775 {} \;
## Recursively change file permission of /var/www & subdir to add group write perm
sudo find /var/www -type f -exec sudo chmod 0664 {} \;
 
## Restart Apache
sudo systemctl restart httpd
sudo service httpd restart
 
## Enable httpd 
sudo systemctl enable httpd 
sudo /sbin/sysctl -w net.ipv4.tcp_keepalive_time=200 net.ipv4.tcp_keepalive_intvl=200 net.ipv4.tcp_keepalive_probes=5


# Fetch the public IPV4 of the instance
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
PUBLIC_IPV4=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/public-ipv4)

# Run the following CliXX_Deployment_Update_Statements to refresh the webpage to update the IP address 
mysql -u ${WordPress_DB_USER} -p${WordPress_DB_PASS} -h ${WordPress_DB_HOST} -D ${WordPress_DB_NAME} <<EOF
    UPDATE wp_options SET option_value = "${PUBLIC_IPV4}" WHERE option_name = "home";
    UPDATE wp_options SET option_value = "${PUBLIC_IPV4}" WHERE option_name = "siteurl";
    UPDATE wp_options SET option_value = "${PUBLIC_IPV4}" WHERE option_name = "ping_sites";
    UPDATE wp_options SET option_value = "${PUBLIC_IPV4}" WHERE option_name = "open_shop_header_retina_logo";
EOF
'''

# Create EC2 resource
ec2_resource = boto3.resource('ec2',region_name=aws_region,aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'])

# Create New Instance
instances = ec2_resource.create_instances(
    MinCount = 1,
    MaxCount = 1,
    ImageId=ami_id,
    InstanceType='t2.micro',
    KeyName=key_pair_name,
    SecurityGroupIds = [security_group_id],
    SubnetId=subnet_id,
    UserData=user_data,
    TagSpecifications=[
        {
            'ResourceType': 'instance',
            'Tags': [
                {
                    'Key': 'Name',
                    'Value': 'CLiXX'
                },
            ]
        },
    ]
)

for instance in instances:
    print(f'EC2 instance "{instance.id}" has been launched')
    instance.wait_until_running()

  

    #EC2_CLIENT.associate_iam_instance_profile(
    #    IamInstanceProfile = {'Name': INSTANCE_PROFILE},
    #    InstanceId = instance.id,
    #)
    
    #print(f'EC2 instance "{instance.id}" has been started')
    #print(f'EC2 Instance Profile "{INSTANCE_PROFILE}" has been attached')