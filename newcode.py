import csv
import boto3
import logging
import io
import os
import time
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(level=logging.INFO)
Logger = logging.getLogger(__name__)

# Environment variables
S3_BUCKET_NAME = os.environ.get('S3_BUCKET_NAME', 'par-dnsresolver')
S3_FILE_NAME = os.environ.get('S3_FILE_NAME', 'dns_records.csv')
MAIN_REGION = os.environ.get('AWS_REGION', 'us-east-1')
INTERMEDIATE_ROLE_ARN = os.environ.get('INTERMEDIATE_ROLE_ARN', 'arn:aws:iam::211125782569:role/SecurityAuditRole')
FINAL_ROLE_ARN_TEMPLATE = os.environ.get('FINAL_ROLE_ARN_TEMPLATE', 'arn:aws:iam::{account_id}:role/SecurityAuditRole')

Header = [
    "Account ID", "Region", "Record Name", "Record Type", "TTL", "Zone Type",
    "Hosted Zone ID", "Load Balancer ARN", "Listener ID", "Target Group Name",
    "TLS", "HealthCheckEnabled", "HealthCheckProtocol", "HealthCheckPort", "HealthCheckPath",
]


def lambda_handler(event, context):
    lambda_role = check_lambda_role()
    if not lambda_role:
        return {'statusCode': 500, 'body': 'Failed to get Lambda identity'}

    csv_buffer = io.StringIO()
    writer = csv.writer(csv_buffer)
    writer.writerow(Header)
    
    # Use Organizations API to list accounts
    org_client = boto3.client('organizations')
    try:
        accounts = list_accounts(org_client)
    except ClientError as e:
        Logger.error(f"Error listing accounts: {str(e)}")
        return {'statusCode': 500, 'body': f"Error listing accounts: {str(e)}"}

    # Assume the intermediate role once
    intermediate_credentials = assume_intermediate_role()
    if not intermediate_credentials:
        return {'statusCode': 500, 'body': 'Failed to assume intermediate role'}

    for account in accounts:
        account_id = account['Id']
        Logger.info(f"Attempting to enter account {account_id}")
        
        # Assume the final role for this account
        assumed_credentials = assume_final_role(account_id, intermediate_credentials)
        if assumed_credentials:
            Logger.info(f"Successfully entered account {account_id}")
            process_account(writer, account_id, assumed_credentials)
            Logger.info(f"Finished processing account {account_id}")
        else:
            Logger.error(f"Failed to enter account {account_id}")
        
        # We don't need to explicitly return to the intermediate role,
        # as the credentials will expire naturally and the next iteration
        # will start fresh from the intermediate role
    
    upload_to_s3(csv_buffer, S3_BUCKET_NAME, S3_FILE_NAME)

    return {'statusCode': 200, 'body': f"CSV file uploaded successfully to s3://{S3_BUCKET_NAME}/{S3_FILE_NAME}"}


def assume_intermediate_role():
    sts_client = boto3.client('sts')
    try:
        Logger.info(f"Attempting to assume intermediate role: {INTERMEDIATE_ROLE_ARN}")
        intermediate_assumed_role = sts_client.assume_role(
            RoleArn=INTERMEDIATE_ROLE_ARN,
            RoleSessionName="IntermediateRoleSession",
            DurationSeconds=3600
        )
        intermediate_credentials = intermediate_assumed_role['Credentials']
        Logger.info(f"Successfully assumed intermediate role")
        return intermediate_credentials
    except ClientError as e:
        Logger.error(f"Error assuming intermediate role: {str(e)}")
        return None

def assume_final_role(account_id, intermediate_credentials):
    sts_client = boto3.client('sts',
        aws_access_key_id=intermediate_credentials['AccessKeyId'],
        aws_secret_access_key=intermediate_credentials['SecretAccessKey'],
        aws_session_token=intermediate_credentials['SessionToken']
    )
    final_role_arn = FINAL_ROLE_ARN_TEMPLATE.format(account_id)
    try:
        Logger.info(f"Attempting to assume final role: {final_role_arn}")
        final_assumed_role = sts_client.assume_role(
            RoleArn=final_role_arn,
            RoleSessionName="FinalRoleSession",
            DurationSeconds=3600
        )
        final_credentials = final_assumed_role['Credentials']
        Logger.info(f"Successfully assumed final role for account {account_id}")
        return final_credentials
    except ClientError as e:
        Logger.error(f"Error assuming final role for account {account_id}: {str(e)}")
        return None
def check_lambda_role():
    sts = boto3.client('sts')
    try:
        identity = sts.get_caller_identity()
        Logger.info(f"Lambda function running as: {identity['Arn']}")
        return identity['Arn']
    except Exception as e:
        Logger.error(f"Failed to get Lambda identity: {str(e)}")
        return None

def assume_role_chain(account_id):
    sts_client = boto3.client('sts')
    
    # First, assume the intermediate role
    try:
        Logger.info(f"Attempting to assume intermediate role: {INTERMEDIATE_ROLE_ARN}")
        intermediate_assumed_role = sts_client.assume_role(
            RoleArn=INTERMEDIATE_ROLE_ARN,
            RoleSessionName="IntermediateRoleSession",
            DurationSeconds=3600
        )
        intermediate_credentials = intermediate_assumed_role['Credentials']
        Logger.info(f"Successfully assumed intermediate role")
    except ClientError as e:
        Logger.error(f"Error assuming intermediate role: {str(e)}")
        return None

    # Create a session with the intermediate role's credentials
    intermediate_session = boto3.Session(
        aws_access_key_id=intermediate_credentials['AccessKeyId'],
        aws_secret_access_key=intermediate_credentials['SecretAccessKey'],
        aws_session_token=intermediate_credentials['SessionToken'],
    )

    sts_client_intermediate = intermediate_session.client('sts')

    # Now, assume the final role in the target account
    final_role_arn = FINAL_ROLE_ARN_TEMPLATE.format(account_id=account_id)
    try:
        Logger.info(f"Attempting to assume final role: {final_role_arn}")
        final_assumed_role = sts_client_intermediate.assume_role(
            RoleArn=final_role_arn,
            RoleSessionName="FinalRoleSession",
            DurationSeconds=3600
        )
        final_credentials = final_assumed_role['Credentials']
        Logger.info(f"Successfully assumed final role for account {account_id}")
        return final_credentials
    except ClientError as e:
        Logger.error(f"Error assuming final role for account {account_id}: {str(e)}")
        return None

def list_accounts(org_client):
    accounts = []
    paginator = org_client.get_paginator('list_accounts')
    for page in paginator.paginate():
        accounts.extend(page['Accounts'])
    return accounts

def process_account(writer, account_id, session):
    Logger.info(f"Starting to process account {account_id}")
    ec2_client = session.client('ec2', region_name=MAIN_REGION)
    try:
        regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
    except ClientError as e:
        Logger.error(f"Error describing regions for account {account_id}: {str(e)}")
        return

    route53 = session.client('route53')

    for region in regions:
        Logger.info(f"Processing region {region} in account {account_id}")
        try:
            elbv2 = session.client('elbv2', region_name=region)

            elbs = retry_with_backoff(lambda: elbv2.describe_load_balancers()['LoadBalancers'])
            for elb in elbs:
                process_elb(writer, account_id, region, elb, elbv2, route53)

            process_non_elb_records(writer, account_id, region, route53)
        except ClientError as e:
            Logger.error(f"Error in account {account_id}, region {region}: {str(e)}")
            continue

def process_elb(writer, account_id, region, elb, elbv2, route53):
    if elb['Type'] in ['network', 'application']:
        dns_map = get_dns_map(route53, elb['DNSName'])
        listeners = elbv2.describe_listeners(LoadBalancerArn=elb['LoadBalancerArn'])['Listeners']
        for listener in listeners:
            process_listener(writer, account_id, region, elb, listener, elbv2, dns_map)

def get_dns_map(route53, elb_dns_name):
    dns_map = {}
    for hosted_zone in route53.list_hosted_zones()['HostedZones']:
        records = route53.list_resource_record_sets(HostedZoneId=hosted_zone['Id'])['ResourceRecordSets']
        for record in records:
            if record['Name'] == elb_dns_name or ('AliasTarget' in record and record['AliasTarget']['DNSName'] == elb_dns_name):
                dns_map[record['Name']] = {
                    "rec_type": record['Type'],
                    "zone_type": 'private' if hosted_zone.get('Config', {}).get('PrivateZone') else 'public',
                    "hosted_zone_id": hosted_zone['Id'],
                    "ttl": record.get('TTL', 'N/A')
                }
    return dns_map

def process_listener(writer, account_id, region, elb, listener, elbv2, dns_map):
    rules = elbv2.describe_rules(ListenerArn=listener['ListenerArn'])['Rules']
    target_group_arns = [action['TargetGroupArn'] for rule in rules for action in rule['Actions'] if 'TargetGroupArn' in action]
    
    for target_group_arn in target_group_arns:
        target_group = elbv2.describe_target_groups(TargetGroupArns=[target_group_arn])['TargetGroups'][0]
        for rec_name, rec_info in dns_map.items():
            write_row(
                writer=writer,
                account_id=account_id,
                region=region,
                rec_name=rec_name,
                rec_type=rec_info["rec_type"],
                ttl=rec_info["ttl"],
                zone_type=rec_info["zone_type"],
                hosted_zone_id=rec_info["hosted_zone_id"],
                elb_arn=elb['LoadBalancerArn'],
                listener_id=listener['ListenerArn'].split('/')[-1],
                target_group_name=target_group['TargetGroupName'],
                tls=listener.get('SslPolicy', 'N/A'),
                health_check_enabled=target_group['HealthCheckEnabled'],
                health_check_protocol=target_group['HealthCheckProtocol'],
                health_check_port=target_group['HealthCheckPort'],
                health_check_path=target_group.get('HealthCheckPath', 'N/A'),
            )

def process_non_elb_records(writer, account_id, region, route53):
    Logger.debug("Processing non-ELB records")
    for zone in route53.list_hosted_zones()['HostedZones']:
        records = route53.list_resource_record_sets(HostedZoneId=zone['Id'])['ResourceRecordSets']
        for record in records:
            write_row(
                writer=writer,
                account_id=account_id,
                region=region,
                rec_name=record['Name'],
                rec_type=record['Type'],
                ttl=record.get('TTL', 'N/A'),
                zone_type='private' if zone.get('Config', {}).get('PrivateZone') else 'public',
                hosted_zone_id=zone['Id'],
                elb_arn='N/A',
                listener_id='N/A',
                target_group_name='N/A',
                tls='N/A',
                health_check_enabled='N/A',
                health_check_protocol='N/A',
                health_check_port='N/A',
                health_check_path='N/A'
            )

def write_row(writer, account_id, region, rec_name, rec_type, ttl, zone_type, hosted_zone_id, elb_arn, listener_id, target_group_name, tls, health_check_enabled, health_check_protocol, health_check_port, health_check_path):
    writer.writerow([
        account_id, region, rec_name, rec_type, ttl, zone_type,
        hosted_zone_id, elb_arn, listener_id, target_group_name, tls,
        health_check_enabled, health_check_protocol, health_check_port, health_check_path
    ])

def upload_to_s3(csv_buffer, bucket_name, file_name):
    s3 = boto3.client('s3')
    try:
        s3.put_object(Bucket=bucket_name, Key=file_name, Body=csv_buffer.getvalue())
        Logger.info(f"Successfully uploaded CSV file to s3://{bucket_name}/{file_name}")
    except ClientError as e:
        Logger.error(f"Error uploading CSV file to s3: {str(e)}")

def retry_with_backoff(func, max_attempts=3, initial_delay=1):
    attempts = 0
    delay = initial_delay
    while attempts < max_attempts:
        try:
            return func()
        except ClientError as e:
            attempts += 1
            if attempts < max_attempts:
                Logger.warning(f"Retry {attempts}/{max_attempts} due to error: {e}. Retrying in {delay} seconds...")
                time.sleep(delay)
                delay *= 2
            else:
                raise