import csv
import boto3
import logging
import io
import os
import time
import json
from botocore.exceptions import ClientError

# Configure logging for CloudWatch
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Environment variables
S3_BUCKET_NAME = os.environ.get('S3_BUCKET_NAME', 'par-dnsresolver')
S3_FILE_NAME = os.environ.get('S3_FILE_NAME', 'dns_records.csv')
S3_ACCOUNTS_FILE_NAME = os.environ.get('S3_ACCOUNTS_FILE_NAME', 'account_list.json')
S3_MANAGEMENT_DNS_FILE = 'dns_management.csv'
MAIN_REGION = os.environ.get('AWS_REGION', 'us-east-1')
MANAGEMENT_ACCOUNT_ID = 'xxxxxxxxxxxxx'
LAMBDA_ACCOUNT_ID = '211125782569'

Header = [
    "Account ID", "Region", "Record Name", "Record Type", "TTL", "Zone Type",
    "Hosted Zone ID", "Load Balancer ARN", "Listener ID", "Target Group Name",
    "TLS", "HealthCheckEnabled", "HealthCheckProtocol", "HealthCheckPort", "HealthCheckPath",
]


def lambda_handler(event, context):
    logger.info("Lambda function started")
    
    try:
        # Step 1: Assume SecurityAuditRole in Lambda account
        logger.info(f"Lambda role assuming SecurityAuditRole in Lambda account ({LAMBDA_ACCOUNT_ID})")
        lambda_security_audit_role = assume_role(LAMBDA_ACCOUNT_ID, 'SecurityAuditRole')
        if not lambda_security_audit_role:
            logger.error("Failed to assume SecurityAuditRole in Lambda account")
            return {'statusCode': 500, 'body': 'Failed to assume SecurityAuditRole in Lambda account'}
        
        # Step 2: Assume SecurityAuditRole in management account
        logger.info(f"Assuming SecurityAuditRole in management account ({MANAGEMENT_ACCOUNT_ID})")
        management_security_audit_role = assume_role(MANAGEMENT_ACCOUNT_ID, 'SecurityAuditRole', lambda_security_audit_role)
        if not management_security_audit_role:
            logger.error("Failed to assume SecurityAuditRole in management account")
            return {'statusCode': 500, 'body': 'Failed to assume SecurityAuditRole in management account'}
        
        # Step 3: List accounts using management role
        set_aws_credentials(management_security_audit_role)
        org_client = boto3.client('organizations', region_name=MAIN_REGION)
        accounts = list_accounts(org_client)
        upload_account_list_to_s3(accounts, S3_BUCKET_NAME, S3_ACCOUNTS_FILE_NAME)
        
        # Step 4: Process management account DNS records
        logger.info("Processing management account DNS records")
        management_csv_buffer = io.StringIO()
        management_writer = csv.writer(management_csv_buffer)
        management_writer.writerow(Header)
        process_account(management_writer, MANAGEMENT_ACCOUNT_ID)
        upload_to_s3(management_csv_buffer, S3_BUCKET_NAME, S3_MANAGEMENT_DNS_FILE)

        # Step 5: Exit management account role and go back to Lambda SecurityAuditRole
        unset_aws_credentials()
        set_aws_credentials(lambda_security_audit_role)

        csv_buffer = io.StringIO()
        writer = csv.writer(csv_buffer)
        writer.writerow(Header)
        
        # Step 6: Process all other accounts
        for account in accounts:
            account_id = account['Id']
            if account_id != MANAGEMENT_ACCOUNT_ID:
                logger.info(f"Processing account: {account_id}")
                account_role = assume_role(account_id, 'SecurityAuditRole', lambda_security_audit_role)
                if account_role:
                    set_aws_credentials(account_role)
                    process_account(writer, account_id)
                    unset_aws_credentials()
                else:
                    logger.error(f"Failed to assume role for account {account_id}")
        
        # Reset to Lambda SecurityAuditRole credentials
        set_aws_credentials(lambda_security_audit_role)
        upload_to_s3(csv_buffer, S3_BUCKET_NAME, S3_FILE_NAME)

    except ClientError as e:
        logger.error(f"Credentials error: {str(e)}")
        return {'statusCode': 500, 'body': f"Credentials error: {str(e)}"}

    logger.info("Lambda function completed successfully")
    return {'statusCode': 200, 'body': f"CSV files uploaded successfully to S3 bucket {S3_BUCKET_NAME}"}


def assume_role(account_id, role_name='SecurityAuditRole', source_credentials=None):
    if source_credentials:
        sts = boto3.client('sts',
                           aws_access_key_id=source_credentials['AccessKeyId'],
                           aws_secret_access_key=source_credentials['SecretAccessKey'],
                           aws_session_token=source_credentials['SessionToken'],
                           region_name=MAIN_REGION)
    else:
        sts = boto3.client('sts', region_name=MAIN_REGION)
    
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    try:
        logger.info(f"Attempting to assume role: {role_arn}")
        assumed_role = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="AssumeRoleSession",
            DurationSeconds=3600
        )
        logger.info(f"Successfully assumed role for account {account_id}")
        return assumed_role['Credentials']
    except ClientError as e:
        logger.error(f"Error assuming role for account {account_id}: {str(e)}")
        return None


def set_aws_credentials(credentials):
    os.environ['AWS_ACCESS_KEY_ID'] = credentials['AccessKeyId']
    os.environ['AWS_SECRET_ACCESS_KEY'] = credentials['SecretAccessKey']
    os.environ['AWS_SESSION_TOKEN'] = credentials['SessionToken']
    

def unset_aws_credentials():
    os.environ.pop('AWS_ACCESS_KEY_ID', None)
    os.environ.pop('AWS_SECRET_ACCESS_KEY', None)
    os.environ.pop('AWS_SESSION_TOKEN', None)


def list_accounts(org_client):
    accounts = []
    paginator = org_client.get_paginator('list_accounts')
    for page in paginator.paginate():
        accounts.extend(page['Accounts'])
    return accounts


def process_account(writer, account_id):
    logger.info(f"Processing DNS records for account {account_id}")
    
    session = boto3.Session()
    ec2_client = session.client('ec2', region_name=MAIN_REGION)
    regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

    route53 = session.client('route53')

    for region in regions:
        logger.info(f"Processing region {region} in account {account_id}")
        try:
            elbv2 = session.client('elbv2', region_name=region)

            elbs = retry_with_backoff(lambda: elbv2.describe_load_balancers()['LoadBalancers'])
            for elb in elbs:
                process_elb(writer, account_id, region, elb, elbv2, route53)

            process_non_elb_records(writer, account_id, region, route53)
        except ClientError as e:
            logger.error(f"Error in account {account_id}, region {region}: {str(e)}")
            continue
        

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
    elb_dns_name = elb['DNSName'].lower()
    for dns_name, dns_info in dns_map.items():
        if elb_dns_name in dns_name.lower():
            tls = 'Yes' if listener['Protocol'] in ['HTTPS', 'TLS'] else 'No'
            target_group_arn = listener['DefaultActions'][0].get('TargetGroupArn')
            target_group_name = 'N/A'
            health_check_enabled = 'N/A'
            health_check_protocol = 'N/A'
            health_check_port = 'N/A'
            health_check_path = 'N/A'

            if target_group_arn:
                target_group = retry_with_backoff(lambda: elbv2.describe_target_groups(TargetGroupArns=[target_group_arn])['TargetGroups'][0])
                target_group_name = target_group['TargetGroupName']
                health_check = target_group.get('HealthCheckEnabled', False)
                health_check_enabled = 'Yes' if health_check else 'No'
                if health_check:
                    health_check_protocol = target_group.get('HealthCheckProtocol', 'N/A')
                    health_check_port = str(target_group.get('HealthCheckPort', 'N/A'))
                    health_check_path = target_group.get('HealthCheckPath', 'N/A')

            writer.writerow([
                account_id, region, dns_name, dns_info['Type'], dns_info['TTL'],
                dns_info['ZoneType'], dns_info['ZoneId'], elb['LoadBalancerArn'],
                listener['ListenerArn'], target_group_name, tls,
                health_check_enabled, health_check_protocol, health_check_port, health_check_path
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
                    writer.writerow([
                        account_id, region, record['Name'], record['Type'],
                        record.get('TTL', 'N/A'), zone_type, zone_id,
                        'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A', 'N/A'
                    ])
                    

def retry_with_backoff(func, max_retries=5, initial_wait=1):
    retries = 0
    while retries < max_retries:
        try:
            return func()
        except ClientError as e:
            if e.response['Error']['Code'] in ['Throttling', 'RequestLimitExceeded']:
                wait_time = initial_wait * (2 ** retries)
                logger.warning(f"Rate limited. Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
                retries += 1
            else:
                raise
            
    raise Exception("Max retries reached")


def upload_to_s3(csv_buffer, bucket, file_name):
    s3 = boto3.client('s3')
    csv_buffer.seek(0)
    s3.put_object(Bucket=bucket, Key=file_name, Body=csv_buffer.getvalue())
    logger.info(f"Uploaded {file_name} to S3 bucket {bucket}")


def upload_account_list_to_s3(accounts, bucket, file_name):
    s3 = boto3.client('s3')
    account_data = json.dumps(accounts)
    s3.put_object(Bucket=bucket, Key=file_name, Body=account_data)
    logger.info(f"Uploaded account list to S3 bucket {bucket} as {file_name}")
    

# Entry point for Lambda
if __name__ == "__main__":
    lambda_handler(None, None)