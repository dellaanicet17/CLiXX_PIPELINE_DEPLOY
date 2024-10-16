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

##################### Delete the DB instance
response = rds_client.delete_db_instance(
    DBInstanceIdentifier='wordpressdbclixx',  # Replace with your DB instance identifier
    SkipFinalSnapshot=True,  # Set to False if you want to create a final snapshot before deletion
   DeleteAutomatedBackups=True  # Optional, deletes all automated backups
)
print("DB Instance deletion initiated:", response)

################### Delete Application Load Balancer
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

##################### Delete mount target befor deleting efs file
# Specify the EFS name
efs_name = 'CLiXX-EFS'
# Describe all file systems
fs_info = efs_client.describe_file_systems()
file_system_id = None
# Find the file system with the specified name
for fs in fs_info['FileSystems']:
    tags = efs_client.list_tags_for_resource(ResourceId=fs['FileSystemId'])['Tags']
    if any(tag['Key'] == 'Name' and tag['Value'] == efs_name for tag in tags):
        file_system_id = fs['FileSystemId']
        print(f"Found EFS with File System ID: {file_system_id}")
        break

if file_system_id is None:
    print(f"No EFS found with the name '{efs_name}'.")
else:
    # Retrieve all mount targets for the specified EFS
    mount_targets_info = efs_client.describe_mount_targets(FileSystemId=file_system_id)
    mount_target_ids = [mount['MountTargetId'] for mount in mount_targets_info['MountTargets']]

    # Delete each mount target
    for mount_target_id in mount_target_ids:
        efs_client.delete_mount_target(MountTargetId=mount_target_id)
        print(f"Deleted mount target: {mount_target_id}")

        # Wait for the mount target to be deleted
        while True:
            time.sleep(5)
            mount_target_info = efs_client.describe_mount_targets(FileSystemId=file_system_id)

            if not any(mount['MountTargetId'] == mount_target_id for mount in mount_target_info['MountTargets']):
                print(f"Mount target {mount_target_id} is deleted.")
                break

    # Delete the EFS file system after all mount targets are deleted
    efs_client.delete_file_system(FileSystemId=file_system_id)
    print(f"Deleted EFS with File System ID: {file_system_id}")

#################### Delete Target Group
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

################## Delete Route 53 record for the load balancer
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

#################### Delete Auto Scaling Group 
# Specify the Auto Scaling Group Name
autoscaling_group_name = 'CLiXX-ASG'

# Delete the Auto Scaling Group
response = autoscaling_client.delete_auto_scaling_group(
    AutoScalingGroupName=autoscaling_group_name,
    ForceDelete=True  # Forces deletion even if there are instances running
)
print("Auto Scaling Group deleted:", response)

# Check if the Auto Scaling Group is deleted
while True:
    time.sleep(120)  # Wait for a few seconds
    asg_status = autoscaling_client.describe_auto_scaling_groups(
        AutoScalingGroupNames=[autoscaling_group_name]
    )
    if not asg_status['AutoScalingGroups']:
        print(f"Auto Scaling Group '{autoscaling_group_name}' deleted successfully.")
        break

#################### Delete Launch Template
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

#################### Fetch and Delete Security Group
# Fetch security group by name
sg_name = 'Test_Stack_Web_DMZ'  # Replace with your security group name

# Describe all security groups
security_groups = ec2_client.describe_security_groups(
    Filters=[{'Name': 'group-name', 'Values': [sg_name]}]
)

# Fetch the security group ID
if security_groups['SecurityGroups']:
    security_group_id = security_groups['SecurityGroups'][0]['GroupId']
    print(f"Found Security Group with ID: {security_group_id}")
    
    # Check if the Auto Scaling Group is deleted before proceeding
    if 'AutoScalingGroupName' in locals() and not asg_status['AutoScalingGroups']:
        response = ec2_client.delete_security_group(
            GroupId=security_group_id
        )
        print("Security Group deleted:", response)
else:
    print(f"Security Group '{sg_name}' not found.")

