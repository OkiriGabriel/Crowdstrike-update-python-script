import csv
import boto3
import logging
import io
import os
from botocore.exceptions import NoCredentialsError, PartialCredentialsError

# Configure logging
logging.basicConfig(level=logging.INFO)
Logger = logging.getLogger(__name__)

# Environment variables
S3_BUCKET_NAME = os.environ.get('S3_BUCKET_NAME', 'awsbucketew')
S3_FILE_NAME = os.environ.get('S3_FILE_NAME', 'dns_records.csv')
MAIN_REGION = os.environ.get('AWS_REGION', 'us-east-1')  # This is used for initial AWS clients

Header = [
    "Account ID",
    "Region",
    "Record Name",
    "Record Type",
    "TTL",
    "Zone Type",
    "Hosted Zone ID",
    "Load Balancer ARN",
    "Listener ID",
    "Target Group Name",
    "TLS",
    "HealthCheckEnabled",
    "HealthCheckProtocol",
    "HealthCheckPort",
    "HealthCheckPath",
]

def main():
    try:
        org_client = boto3.client('organizations', region_name=MAIN_REGION)
    except (NoCredentialsError, PartialCredentialsError) as e:
        Logger.error(f"Credentials error: {str(e)}")
        return

    # Create a CSV file in memory
    csv_buffer = io.StringIO()
    writer = csv.writer(csv_buffer)
    writer.writerow(Header)
    
    # List all accounts in the organization
    accounts = list_accounts(org_client)

    # Process each account
    for account in accounts:
        account_id = account['Id']
        session = assume_role(account_id)
        if session:
            process_account(writer, account_id, session)
    
    # Upload to S3
    upload_to_s3(csv_buffer, S3_BUCKET_NAME, S3_FILE_NAME)

def list_accounts(org_client):
    accounts = []
    paginator = org_client.get_paginator('list_accounts')
    for page in paginator.paginate():
        accounts.extend(page['Accounts'])
    return accounts

def assume_role(account_id):
    sts = boto3.client('sts')
    role_arn = f"arn:aws:iam::{account_id}:role/CrossAccountRole"
    try:
        assumed_role = sts.assume_role(RoleArn=role_arn, RoleSessionName="AssumeRoleSession")
        credentials = assumed_role['Credentials']
        session = boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
        )
        return session
    except Exception as e:
        Logger.error(f"Error assuming role for account {account_id}: {str(e)}")
        return None

def process_account(writer, account_id, session):
    # Get list of all regions
    ec2_client = session.client('ec2', region_name=MAIN_REGION)
    regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

    # Create Route53 client (global service, no need for region)
    route53 = session.client('route53')

    for region in regions:
        Logger.info(f"Processing account {account_id} in region {region}")
        
        # Create regional ELBv2 client
        elbv2 = session.client('elbv2', region_name=region)

        seen = {}
        try:
            for elb in elbv2.describe_load_balancers()['LoadBalancers']:
                Logger.debug(f"Processing ELB {elb['LoadBalancerArn']}")
                if elb['Type'] in ['network', 'application']:
                    dns_map = {}
                    for hosted_zone in route53.list_hosted_zones()['HostedZones']:
                        records = route53.list_resource_record_sets(HostedZoneId=hosted_zone['Id'])['ResourceRecordSets']
                        for record in records:
                            if record['Name'] == elb['DNSName'] or ('AliasTarget' in record and record['AliasTarget']['DNSName'] == elb['DNSName']):
                                dns_map[record['Name']] = {
                                    "rec_type": record['Type'],
                                    "zone_type": 'private' if hosted_zone.get('Config', {}).get('PrivateZone') else 'public',
                                    "hosted_zone_id": hosted_zone['Id'],
                                    "ttl": record.get('TTL', 'N/A')
                                }

                    listeners = elbv2.describe_listeners(LoadBalancerArn=elb['LoadBalancerArn'])['Listeners']
                    for listener in listeners:
                        target_group_arns = []
                        rules = elbv2.describe_rules(ListenerArn=listener['ListenerArn'])['Rules']
                        for rule in rules:
                            for action in rule['Actions']:
                                if 'TargetGroupArn' in action:
                                    target_group_arns.append(action['TargetGroupArn'])

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

                                seen[rec_name] = True
        except Exception as e:
            Logger.error(f"Error processing ELBs in account {account_id}, region {region}: {str(e)}")

        Logger.debug("Processing non-ELB records")

        for zone in route53.list_hosted_zones()['HostedZones']:
            records = route53.list_resource_record_sets(HostedZoneId=zone['Id'])['ResourceRecordSets']
            for rec in records:
                Logger.debug(f"Processing record {rec['Name']}")
                if rec['Name'] not in seen:
                    if rec['Type'] in ["A", "CNAME"]:
                        ttl = rec.get('TTL', 'N/A')
                        write_row(
                            writer=writer,
                            account_id=account_id,
                            region=region,
                            rec_name=rec['Name'],
                            rec_type=rec['Type'],
                            ttl=ttl,
                            zone_type='private' if zone.get('Config', {}).get('PrivateZone') else 'public',
                            hosted_zone_id=zone['Id'],
                        )

def write_row(
    writer,
    account_id,
    region,
    rec_name,
    rec_type,
    ttl,
    zone_type,
    hosted_zone_id,
    elb_arn=None,
    listener_id=None,
    target_group_name=None,
    tls=None,
    health_check_enabled=False,
    health_check_protocol=None,
    health_check_port=None,
    health_check_path=None,
):
    row = [account_id, region, rec_name, rec_type, ttl, zone_type, hosted_zone_id,
           elb_arn or "N/A", listener_id or "N/A", target_group_name or "N/A",
           tls or "N/A", health_check_enabled or False, health_check_protocol or "N/A",
           health_check_port or "N/A", health_check_path or "N/A"]
    writer.writerow(row)

def upload_to_s3(csv_buffer, bucket, s3_file):
    s3 = boto3.client('s3')
    try:
        s3.put_object(Bucket=bucket, Key=s3_file, Body=csv_buffer.getvalue())
        Logger.info(f"Upload Successful: {s3_file} to {bucket}")
    except Exception as e:
        Logger.error(f"Error uploading to S3: {str(e)}")

if __name__ == "__main__":
    main()