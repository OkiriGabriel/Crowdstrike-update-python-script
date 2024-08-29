import csv
import io
import boto3
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    output = io.StringIO()
    writer = csv.writer(output)
    
    Header = [
        "Account ID", "Region", "Record Name", "Record Type", "TTL", "Zone Type",
        "Load Balancer ARN", "Listener ID", "Target Group Name", "TLS",
        "HealthCheckEnabled", "HealthCheckProtocol", "HealthCheckPort", "HealthCheckPath",
    ]
    
    writer.writerow(Header)

    # Get the list of accounts
    organizations = boto3.client('organizations')
    try:
        accounts = organizations.list_accounts()['Accounts']
    except ClientError as e:
        print(f"Error listing accounts: {e}")
        return {
            'statusCode': 500,
            'body': f'Error listing accounts: {str(e)}'
        }

    for account in accounts:
        process_account(account['Id'], writer)

    # Get the CSV content as a string
    csv_content = output.getvalue()
    output.close()

    # Save to S3 in the account where the Lambda is running
    s3 = boto3.client('s3')
    bucket_name = 'your-bucket-name'  # Replace with your actual bucket name
    file_name = 'multi_account_dns_records.csv'
    try:
        s3.put_object(Bucket=bucket_name, Key=file_name, Body=csv_content)
    except ClientError as e:
        print(f"Error saving to S3: {e}")
        return {
            'statusCode': 500,
            'body': f'Error saving to S3: {str(e)}'
        }

    return {
        'statusCode': 200,
        'body': f'CSV file successfully generated and saved to s3://{bucket_name}/{file_name}'
    }

def process_account(account_id, writer):
    # Assume the role in the target account
    sts = boto3.client('sts')
    role_arn = f'arn:aws:iam::{account_id}:role/YourCrossAccountRoleName'  # Replace with your actual role name
    try:
        assumed_role = sts.assume_role(RoleArn=role_arn, RoleSessionName="DNSAuditSession")
    except ClientError as e:
        print(f"Error assuming role in account {account_id}: {e}")
        return

    # Create a new session with the assumed role credentials
    session = boto3.Session(
        aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
        aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
        aws_session_token=assumed_role['Credentials']['SessionToken']
    )
    
    route53 = session.client('route53')
    
    # Get all regions
    ec2 = session.client('ec2')
    try:
        regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
    except ClientError as e:
        print(f"Error describing regions in account {account_id}: {e}")
        return
    
    for region in regions:
        elbv2 = session.client('elbv2', region_name=region)
        process_route53_records(account_id, region, route53, elbv2, writer)

def process_route53_records(account_id, region, route53, elbv2, writer):
    try:
        elbs = get_elbs(elbv2)
        paginator = route53.get_paginator('list_hosted_zones')
        for page in paginator.paginate():
            for zone in page['HostedZones']:
                zone_id = zone['Id']
                zone_type = 'Private' if zone.get('Config', {}).get('PrivateZone') else 'Public'
                record_paginator = route53.get_paginator('list_resource_record_sets')
                for record_page in record_paginator.paginate(HostedZoneId=zone_id):
                    for record in record_page['ResourceRecordSets']:
                        elb_info = get_elb_info(record, elbs, elbv2)
                        writer.writerow([
                            account_id, region, record['Name'], record['Type'],
                            record.get('TTL', 'N/A'), zone_type,
                            elb_info['LoadBalancerArn'], elb_info['ListenerId'],
                            elb_info['TargetGroupName'], elb_info['TLS'],
                            elb_info['HealthCheckEnabled'], elb_info['HealthCheckProtocol'],
                            elb_info['HealthCheckPort'], elb_info['HealthCheckPath'],
                        ])
    except ClientError as e:
        print(f"Error processing Route 53 records in account {account_id}, region {region}: {e}")

def get_elbs(elbv2):
    elbs = {}
    try:
        paginator = elbv2.get_paginator('describe_load_balancers')
        for page in paginator.paginate():
            for lb in page['LoadBalancers']:
                elbs[lb['DNSName']] = lb['LoadBalancerArn']
    except ClientError as e:
        print(f"Error describing load balancers: {e}")
    return elbs

def get_elb_info(record, elbs, elbv2):
    default_info = {
        'LoadBalancerArn': 'N/A', 'ListenerId': 'N/A', 'TargetGroupName': 'N/A',
        'TLS': 'N/A', 'HealthCheckEnabled': 'N/A', 'HealthCheckProtocol': 'N/A',
        'HealthCheckPort': 'N/A', 'HealthCheckPath': 'N/A',
    }

    if 'AliasTarget' in record:
        elb_dns_name = record['AliasTarget']['DNSName']
        if elb_dns_name in elbs:
            lb_arn = elbs[elb_dns_name]
            return get_elb_details(elbv2, lb_arn)
    
    return default_info

def get_elb_details(elbv2, lb_arn):
    try:
        listeners = elbv2.describe_listeners(LoadBalancerArn=lb_arn)['Listeners']
        listener = listeners[0] if listeners else {}
        target_groups = elbv2.describe_target_groups(LoadBalancerArn=lb_arn)['TargetGroups']
        tg = target_groups[0] if target_groups else {}

        return {
            'LoadBalancerArn': lb_arn,
            'ListenerId': listener.get('ListenerArn', 'N/A'),
            'TargetGroupName': tg.get('TargetGroupName', 'N/A'),
            'TLS': listener.get('SslPolicy', 'N/A'),
            'HealthCheckEnabled': tg.get('HealthCheckEnabled', 'N/A'),
            'HealthCheckProtocol': tg.get('HealthCheckProtocol', 'N/A'),
            'HealthCheckPort': tg.get('HealthCheckPort', 'N/A'),
            'HealthCheckPath': tg.get('HealthCheckPath', 'N/A'),
        }
    except ClientError as e:
        print(f"Error getting ELB details: {e}")
        return {key: 'N/A' for key in [
            'LoadBalancerArn', 'ListenerId', 'TargetGroupName', 'TLS',
            'HealthCheckEnabled', 'HealthCheckProtocol', 'HealthCheckPort', 'HealthCheckPath'
        ]}