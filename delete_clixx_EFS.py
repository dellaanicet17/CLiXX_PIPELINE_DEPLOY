#!/usr/bin/env python3
import boto3, botocore, base64

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

##################### Step 1: Delete the DB instance
response = rds_client.delete_db_instance(
    DBInstanceIdentifier='wordpressdbclixx',  # Replace with your DB instance identifier
    SkipFinalSnapshot=True,  # Set to False if you want to create a final snapshot before deletion
   DeleteAutomatedBackups=True  # Optional, deletes all automated backups
)
print("DB Instance deletion initiated:", response)

##################### Step 2: Delete security Group
response = ec2_client.delete_security_group(
    GroupId='string',
    GroupName='Test_Stack_Web_DMZ'
    )
print(response)

################### Step 3: Delete Application Load Balancer
# Name of the load balancer to delete
lb_name = 'CLiXX-LB'

# Describe all load balancers to find the one with the specified name
load_balancers = elbv2_client.describe_load_balancers()

# Loop through load balancers and find the one with the matching name
for lb in load_balancers['LoadBalancers']:
    if lb['LoadBalancerName'] == lb_name:
        lb_arn = lb['LoadBalancerArn']
        
        # Delete the load balancer using its ARN
        elbv2_client.delete_load_balancer(LoadBalancerArn=lb_arn)
        print(f"Application Load Balancer '{lb_name}' deleted.")
        break

##################### Step 4: Delete EFS file system
# EFS name to delete
efs_name = 'CLiXX-EFS' 

# Fetch all EFS file systems
file_systems = efs_client.describe_file_systems()

# Loop through and find the EFS ID based on the Name tag
for fs in file_systems['FileSystems']:
    tags = efs_client.describe_tags(FileSystemId=fs['FileSystemId'])
    
   # Check if the Name tag matches
    for tag in tags['Tags']:
        if tag['Key'] == 'Name' and tag['Value'] == efs_name:
           file_system_id = fs['FileSystemId']
            
            # Delete the EFS
            efs_client.delete_file_system(FileSystemId=file_system_id)
            print(f"EFS '{efs_name}' with ID '{file_system_id}' deleted.")
            break

#################### Step 5: Delete Target Group
# Name of the target group to delete
tg_name = 'CLiXX-TG'

# Describe all target groups to find the one with the specified name
target_groups = elbv2_client.describe_target_groups()

# Loop through target groups and find the one with the matching name
for tg in target_groups['TargetGroups']:
    if tg['TargetGroupName'] == tg_name:
        tg_arn = tg['TargetGroupArn']

        # Delete the target group using its ARN
        elbv2_client.delete_target_group(TargetGroupArn=tg_arn)
        print(f"Target Group '{tg_name}' deleted.")
        break

################## Step 6: Delete Route 53 record for the load balancer
# Specify your Hosted Zone ID and the record name
hosted_zone_id = 'Z04517273VCLIDX9UEQR7'
record_name = 'test.clixx-della.com'

try:
    # Fetch the record sets
    response = route53_client.list_resource_record_sets(HostedZoneId=hosted_zone_id)

    # Find the record you want to delete
    record_sets = response['ResourceRecordSets']
    
    # Check if the record exists and retrieve the value
    record_value = None
    for record in record_sets:
        if record['Name'] == record_name + '.':  # Note the trailing dot
            record_value = record['ResourceRecords'][0]['Value']
            break

    if record_value:
        # Now proceed to delete the record
        print(f"Deleting record: {record_name} with value: {record_value}")
        route53_client.change_resource_record_sets(
            HostedZoneId=hosted_zone_id,
            ChangeBatch={
                'Changes': [
                    {
                        'Action': 'DELETE',
                        'ResourceRecordSet': {
                            'Name': record_name,
                            'Type': 'A',  # Adjust if the record type is different
                            'TTL': 300,  # Use the TTL that matches the existing record
                            'ResourceRecords': [{'Value': record_value}],
                        }
                    }
                ]
            }
        )
        print(f"Deleted record: {record_name}")
    else:
        print(f"Record {record_name} does not exist.")

except Exception as e:
    print(f"Error: {str(e)}")

#################### Step 7: Delete Auto Scaling Group 
# Specify the Auto Scaling Group Name
autoscaling_group_name = 'CLiXX-ASG'

# Delete the Auto Scaling Group
response = autoscaling_client.delete_auto_scaling_group(
    AutoScalingGroupName=autoscaling_group_name,
    ForceDelete=True  # Forces deletion even if there are instances running
)
print("Auto Scaling Group deleted:", response)

#################### Step 8: Delete Launch Template
# Specify the Launch Template Name
launch_template_name = 'CLiXX-LT'

# Get the Launch Template ID based on the Launch Template Name
response = ec2_client.describe_launch_templates(
    Filters=[{'Name': 'launch-template-name', 'Values': [launch_template_name]}]
)

# Extract the Launch Template ID
launch_template_id = response['LaunchTemplates'][0]['LaunchTemplateId']

# Delete the Launch Template
delete_response = ec2_client.delete_launch_template(
    LaunchTemplateId=launch_template_id
)
print("Launch Template deleted:", delete_response)
