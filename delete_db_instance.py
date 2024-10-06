#!/usr/bin/python

import boto3,botocore

sts_client=boto3.client('sts')

#Calling the assume_role function
assumed_role_object=sts_client.assume_role(RoleArn='arn:aws:iam::495599767034:role/Engineer', RoleSessionName='mysession')

credentials=assumed_role_object['Credentials']

print(credentials)

# Create an RDS client
rds_client = boto3.client('rds',aws_access_key_id=credentials['AccessKeyId'],aws_secret_access_key=credentials['SecretAccessKey'],aws_session_token=credentials['SessionToken'])

# Delete the DB instance
response = rds_client.delete_db_instance(
    DBInstanceIdentifier='wordpressdbclixx',  # Replace with your DB instance identifier
    SkipFinalSnapshot=True,  # Set to False if you want to create a final snapshot before deletion
    DeleteAutomatedBackups=True  # Optional, deletes all automated backups
)

print("DB Instance deletion initiated:", response)