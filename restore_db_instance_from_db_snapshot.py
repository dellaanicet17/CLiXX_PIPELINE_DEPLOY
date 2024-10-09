#!/usr/bin/env python3
import boto3,botocore

sts_client=boto3.client('sts')

#Calling the assume_role function
assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::043309319757:role/Engineer', RoleSessionName='mysession')

credentials=assumed_role_object['Credentials']

print(credentials)

# Create RDS client
rds_client=boto3.client('rds',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'])

# Parameters
db_instance_identifier = 'wordpressdbclixx'
db_snapshot_identifier = 'arn:aws:rds:us-east-1:577701061234:snapshot:wordpressdbclixx-ecs-snapshot'
db_instance_class = 'db.m6gd.large'  # Example instance class
security_group_id = ['sg-024f0157b123d6a8c']  # Your security group IDs SECURITY_GROUP_ID = 'sg-024f0157b123d6a8c'
availabilityzone = 'us-east-1a'
# Restore DB instance from snapshot
response = rds_client.restore_db_instance_from_db_snapshot(
    DBInstanceIdentifier=db_instance_identifier,
    DBSnapshotIdentifier=db_snapshot_identifier,
    DBInstanceClass=db_instance_class,
    VpcSecurityGroupIds=security_group_id,
    AvailabilityZone=availabilityzone,
    MultiAZ=False,
    PubliclyAccessible=True
)

print(response)
