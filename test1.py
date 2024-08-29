import csv
import boto3
import logging
import io
import os
import time
import json
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(level=logging.INFO)
Logger = logging.getLogger(__name__)

# Environment variables
S3_BUCKET_NAME = os.environ.get('S3_BUCKET_NAME', 'par-dnsresolver')
S3_FILE_NAME = os.environ.get('S3_FILE_NAME', 'dns_records.csv')
S3_ACCOUNTS_FILE_NAME = os.environ.get('S3_ACCOUNTS_FILE_NAME', 'account_list.json')
S3_MANAGEMENT_DNS_FILE = 'dns_management.csv'
S3_LAMBDA_DNS_FILE = 'dns_lambda.csv'
MAIN_REGION = os.environ.get('AWS_REGION', 'us-east-1')
MANAGEMENT_ACCOUNT_ID = 'xxxxxxxxxxxxx'
LAMBDA_ACCOUNT_ID = '211125782569'

Header = [
    "Account ID", "Region", "Record Name", "Record Type", "TTL", "Zone Type",
    "Hosted Zone ID", "Load Balancer ARN", "Listener ID", "Target Group Name",
    "TLS", "HealthCheckEnabled", "HealthCheckProtocol", "HealthCheckPort", "HealthCheckPath",
]

def lambda_handler(event, context):
    lambda_role = check_lambda_role()
    if not lambda_role:
        return {'statusCode': 500, 'body': 'Failed to get Lambda identity'}

    try:
        # Step 1: Assume SecurityAuditRole in Lambda account
        security_audit_role = assume_role(LAMBDA_ACCOUNT_ID, 'SecurityAuditRole')
        if not security_audit_role:
            return {'statusCode': 500, 'body': 'Failed to assume SecurityAuditRole in Lambda account'}
        
        # Step 2: Get DNS records for Lambda account
        lambda_csv_buffer = io.StringIO()
        lambda_writer = csv.writer(lambda_csv_buffer)
        lambda_writer.writerow(Header)
        process_account(lambda_writer, LAMBDA_ACCOUNT_ID, security_audit_role)
        upload_to_s3(lambda_csv_buffer, S3_BUCKET_NAME, S3_LAMBDA_DNS_FILE)
        
        # Step 3: Assume role in management account to list accounts and get DNS records
        management_role = assume_role(MANAGEMENT_ACCOUNT_ID, 'SecurityAuditRole', security_audit_role)
        if not management_role:
            return {'statusCode': 500, 'body': 'Failed to assume role in management account'}
        
        org_client = boto3.client(
            'organizations', 
            region_name=MAIN_REGION, 
            aws_access_key_id=management_role['AccessKeyId'],
            aws_secret_access_key=management_role['SecretAccessKey'],
            aws_session_token=management_role['SessionToken']
        )
        accounts = list_accounts(org_client)
        
        # Upload account list to S3
        upload_account_list_to_s3(accounts, S3_BUCKET_NAME, S3_ACCOUNTS_FILE_NAME)

        # Get management account DNS records
        management_csv_buffer = io.StringIO()
        management_writer = csv.writer(management_csv_buffer)
        management_writer.writerow(Header)
        process_account(management_writer, MANAGEMENT_ACCOUNT_ID, management_role)
        upload_to_s3(management_csv_buffer, S3_BUCKET_NAME, S3_MANAGEMENT_DNS_FILE)

        # Step 4: Return to SecurityAuditRole in Lambda account
        security_audit_role = assume_role(LAMBDA_ACCOUNT_ID, 'SecurityAuditRole')
        if not security_audit_role:
            return {'statusCode': 500, 'body': 'Failed to re-assume SecurityAuditRole in Lambda account'}

    except ClientError as e:
        Logger.error(f"Credentials error: {str(e)}")
        return {'statusCode': 500, 'body': f"Credentials error: {str(e)}"}

    csv_buffer = io.StringIO()
    writer = csv.writer(csv_buffer)
    writer.writerow(Header)
    
    # Step 5: Process each account
    for account in accounts:
        account_id = account['Id']
        if account_id != LAMBDA_ACCOUNT_ID and account_id != MANAGEMENT_ACCOUNT_ID:
            process_account(writer, account_id, security_audit_role)
            # After processing each account, re-assume SecurityAuditRole in Lambda account
            security_audit_role = assume_role(LAMBDA_ACCOUNT_ID, 'SecurityAuditRole')
            if not security_audit_role:
                Logger.error(f"Failed to re-assume SecurityAuditRole after processing account {account_id}")
                continue

    upload_to_s3(csv_buffer, S3_BUCKET_NAME, S3_FILE_NAME)

    return {'statusCode': 200, 'body': f"CSV files uploaded successfully to S3 bucket {S3_BUCKET_NAME}"}

def check_lambda_role():
    sts = boto3.client('sts')
    try:
        identity = sts.get_caller_identity()
        Logger.info(f"Lambda function running as: {identity['Arn']}")
        return identity['Arn']
    except Exception as e:
        Logger.error(f"Failed to get Lambda identity: {str(e)}")
        return None

def assume_role(account_id, role_name='SecurityAuditRole', source_credentials=None):
    if source_credentials:
        sts = boto3.client('sts',
                           aws_access_key_id=source_credentials['AccessKeyId'],
                           aws_secret_access_key=source_credentials['SecretAccessKey'],
                           aws_session_token=source_credentials['SessionToken'],
                           region_name='us-east-1',
                           endpoint_url='https://sts.amazonaws.com')
    else:
        sts = boto3.client('sts', region_name='us-east-1', endpoint_url='https://sts.amazonaws.com')
    
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    try:
        Logger.info(f"Attempting to assume role: {role_arn}")
        assumed_role = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="AssumeRoleSession",
            DurationSeconds=3600
        )
        credentials = assumed_role['Credentials']
        Logger.info(f"Successfully assumed role for account {account_id}")
        return credentials
    except ClientError as e:
        Logger.error(f"Error assuming role for account {account_id}: {str(e)}")
        return None

def list_accounts(org_client):
    accounts = []
    paginator = org_client.get_paginator('list_accounts')
    for page in paginator.paginate():
        accounts.extend(page['Accounts'])
    return accounts

def process_account(writer, account_id, security_audit_role):
    Logger.info(f"Starting to process account {account_id}")
    # Assume role in the account we're processing
    account_role = assume_role(account_id, 'SecurityAuditRole', security_audit_role)
    if not account_role:
        Logger.error(f"Failed to assume role for account {account_id}")
        return

    try:
        session = boto3.Session(
            aws_access_key_id=account_role['AccessKeyId'],
            aws_secret_access_key=account_role['SecretAccessKey'],
            aws_session_token=account_role['SessionToken'],
        )

        ec2_client = session.client('ec2', region_name=MAIN_REGION)
        regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

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
    finally:
        # We don't need to explicitly return to SecurityAuditRole as we're using temporary credentials
        pass

def process_elb(writer, account_id, region, elb, elbv2, route53):
    dns_map = get_dns_map(route53)
    listeners = retry_with_backoff(lambda: elbv2.describe_listeners(LoadBalancerArn=elb['LoadBalancerArn'])['Listeners'])
    
    for listener in listeners:
        process_listener(writer, account_id, region, elb, listener, elbv2, dns_map)

def get_dns_map(route53):
    dns_map = {}
    paginator = route53.get_paginator('list_hosted_zones')
    for page in paginator.paginate():
        for zone in page['HostedZones']:
            zone_id = zone['Id'].split('/')[-1]
            records = retry_with_backoff(lambda: route53.list_resource_record_sets(HostedZoneId=zone_id))
            for record in records['ResourceRecordSets']:
                if record['Type'] in ['A', 'AAAA', 'CNAME']:
                    dns_map[record['Name']] = {
                        'ZoneId': zone_id,
                        'ZoneType': 'Private' if zone.get('Config', {}).get('PrivateZone') else 'Public',
                        'TTL': record.get('TTL', 'N/A'),
                        'Type': record['Type']
                    }
    return dns_map

def process_listener(writer, account_id, region, elb, listener, elbv2, dns_map):
    tg_arn = listener['DefaultActions'][0].get('TargetGroupArn')
    if tg_arn:
        tg = retry_with_backoff(lambda: elbv2.describe_target_groups(TargetGroupArns=[tg_arn])['TargetGroups'][0])
        health_check = tg.get('HealthCheckPath', 'N/A')
        health_check_enabled = tg.get('HealthCheckEnabled', 'N/A')
        health_check_protocol = tg.get('HealthCheckProtocol', 'N/A')
        health_check_port = tg.get('HealthCheckPort', 'N/A')
    else:
        health_check = health_check_enabled = health_check_protocol = health_check_port = 'N/A'

    dns_name = elb['DNSName']
    if dns_name in dns_map:
        zone_id = dns_map[dns_name]['ZoneId']
        zone_type = dns_map[dns_name]['ZoneType']
        ttl = dns_map[dns_name]['TTL']
        record_type = dns_map[dns_name]['Type']
    else:
        zone_id = zone_type = ttl = record_type = 'N/A'

    write_row(writer, [
        account_id,
        region,
        dns_name,
        record_type,
        ttl,
        zone_type,
        zone_id,
        elb['LoadBalancerArn'],
        listener['ListenerArn'],
        tg_arn.split('/')[-1] if tg_arn else 'N/A',
        'Yes' if listener.get('SslPolicy') else 'No',
        health_check_enabled,
        health_check_protocol,
        health_check_port,
        health_check
    ])

def process_non_elb_records(writer, account_id, region, route53):
    paginator = route53.get_paginator('list_hosted_zones')
    for page in paginator.paginate():
        for zone in page['HostedZones']:
            zone_id = zone['Id'].split('/')[-1]
            zone_type = 'Private' if zone.get('Config', {}).get('PrivateZone') else 'Public'
            records = retry_with_backoff(lambda: route53.list_resource_record_sets(HostedZoneId=zone_id))
            for record in records['ResourceRecordSets']:
                if record['Type'] in ['A', 'AAAA', 'CNAME']:
                    write_row(writer, [
                        account_id,
                        region,
                        record['Name'],
                        record['Type'],
                        record.get('TTL', 'N/A'),
                        zone_type,
                        zone_id,
                        'N/A',  # LoadBalancerArn
                        'N/A',  # ListenerArn
                        'N/A',  # TargetGroupName
                        'N/A',  # TLS
                        'N/A',  # HealthCheckEnabled
                        'N/A',  # HealthCheckProtocol
                        'N/A',  # HealthCheckPort
                        'N/A'   # HealthCheckPath
                    ])

def write_row(writer, row):
    writer.writerow(row)

def upload_to_s3(csv_buffer, bucket, key):
    s3 = boto3.client('s3')
    try:
        s3.put_object(Bucket=bucket, Key=key, Body=csv_buffer.getvalue())
        Logger.info(f"Successfully uploaded {key} to {bucket}")
    except Exception as e:
        Logger.error(f"Error uploading to S3: {str(e)}")

def upload_account_list_to_s3(accounts, bucket, key):
    s3 = boto3.client('s3')
    try:
        account_list = [{'Id': account['Id'], 'Name': account['Name']} for account in accounts]
        json_data = json.dumps(account_list, indent=2)
        s3.put_object(Bucket=bucket, Key=key, Body=json_data)
        Logger.info(f"Successfully uploaded account list to {bucket}/{key}")
    except Exception as e:
        Logger.error(f"Error uploading account list to S3: {str(e)}")

def retry_with_backoff(func, max_retries=3, base_delay=1):
    for attempt in range(max_retries):
        try:
            return func()
        except ClientError as e:
            if e.response['Error']['Code'] in ['Throttling', 'RequestLimitExceeded']:
                if attempt == max_retries - 1:
                    raise
                delay = base_delay * (2 ** attempt)
                time.sleep(delay)
            else:
                raise

if __name__ == "__main__":
    # This block is for local testing and won't be executed in Lambda
    test_event = {}
    test_context = None
    print(lambda_handler(test_event, test_context))