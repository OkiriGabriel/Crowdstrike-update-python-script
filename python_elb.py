import csv
import io
import boto3

# globals
import logging

Logger = logging.getLogger(__name__)

Header = [
    "Account ID",
    "Region",
    "Record Name",
    "Record Type",
    "TTL",
    "Zone Type",
    "Load Balancer ARN",
    "Listener ID",
    "Target Group Name",
    "TLS",
    "HealthCheckEnabled",
    "HealthCheckProtocol",
    "HealthCheckPort",
    "HealthCheckPath",
]

def lambda_handler(event, context):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(Header)

    # Get the list of accounts
    organizations = boto3.client('organizations')
    accounts = organizations.list_accounts()['Accounts']

    for account in accounts:
        process_account(account['Id'], writer)

    # Get the CSV content as a string
    csv_content = output.getvalue()
    output.close()

    # Save to S3 in the account where the Lambda is running
    s3 = boto3.client('s3')
    bucket_name = 'your-bucket-name'  # Replace with your actual bucket name
    file_name = 'multi_account_dns_records.csv'
    s3.put_object(Bucket=bucket_name, Key=file_name, Body=csv_content)

    return {
        'statusCode': 200,
        'body': f'CSV file successfully generated and saved to s3://{bucket_name}/{file_name}'
    }

def process_account(account_id, writer):
    # Assume the role in the target account
    sts = boto3.client('sts')
    role_arn = f'arn:aws:iam::{account_id}:role/YourCrossAccountRoleName'  
    assumed_role = sts.assume_role(RoleArn=role_arn, RoleSessionName="DNSAuditSession")
    
    # Create a new session with the assumed role credentials
    session = boto3.Session(
        aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
        aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
        aws_session_token=assumed_role['Credentials']['SessionToken']
    )
    
    elbv2 = session.client('elbv2')
    route53 = session.client('route53')

    seen = {}
    for elb in elbv2.describe_load_balancers()['LoadBalancers']:
        Logger.debug(f"Processing ELB {elb['LoadBalancerArn']} in account {account_id}")
        if elb['Type'] in ['network', 'application']:
            region = session.region_name

            # Use Route53 to get the DNS record
            dns_records = route53.list_resource_record_sets(
                HostedZoneId='YOUR_HOSTED_ZONE_ID',  # Replace with actual Hosted Zone ID
                StartRecordName=elb['DNSName'],
                StartRecordType='A',
                MaxItems='1'
            )['ResourceRecordSets']
            
            if dns_records:
                rec_type = dns_records[0]['Type']
                ttl = dns_records[0].get('TTL', 'Unknown')
            else:
                rec_type = "Unknown"
                ttl = "Unknown"

            dns_map = {}
            dns_map[elb['DNSName']] = {"rec_type": rec_type, "zone_type": "public"}

            # Find records by alias target
            for hosted_zone in route53.list_hosted_zones()['HostedZones']:
                records = route53.list_resource_record_sets(HostedZoneId=hosted_zone['Id'])['ResourceRecordSets']
                for record in records:
                    if 'AliasTarget' in record and record['AliasTarget']['DNSName'] == elb['DNSName']:
                        dns_map[record['Name']] = {
                            "rec_type": record['Type'],
                            "zone_type": get_zone_type(route53, hosted_zone['Id']),
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
                    for rec_name in dns_map.keys():
                        write_row(
                            writer=writer,
                            account_id=account_id,
                            region=region,
                            rec_name=rec_name,
                            rec_type=dns_map[rec_name]["rec_type"],
                            ttl=ttl,
                            zone_type=dns_map[rec_name]["zone_type"],
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

    Logger.debug(f"Processing non-ELB records in account {account_id}")

    for zone in route53.list_hosted_zones()['HostedZones']:
        records = route53.list_resource_record_sets(HostedZoneId=zone['Id'])['ResourceRecordSets']
        for rec in records:
            Logger.debug(f"Processing record {rec['Name']} in account {account_id}")
            if rec['Name'] not in seen:
                if rec['Type'] in ["A", "CNAME"]:
                    ttl = rec.get('TTL', 'N/A')
                    write_row(
                        writer=writer,
                        account_id=account_id,
                        region=session.region_name,
                        rec_name=rec['Name'],
                        rec_type=rec['Type'],
                        ttl=ttl,
                        zone_type='private' if zone.get('Config', {}).get('PrivateZone') else 'public',
                    )

def write_row(
    writer,
    account_id,
    region,
    rec_name,
    rec_type,
    ttl,
    zone_type,
    elb_arn=None,
    listener_id=None,
    target_group_name=None,
    tls=None,
    health_check_enabled=False,
    health_check_protocol=None,
    health_check_port=None,
    health_check_path=None,
):
    if elb_arn is None:
        elb_arn = "N/A"
    if listener_id is None:
        listener_id = "N/A"
    if target_group_name is None:
        target_group_name = "N/A"
    if tls is None:
        tls = "N/A"
    if health_check_enabled is None:
        health_check_enabled = False
    if health_check_protocol is None:
        health_check_protocol = "N/A"
    if health_check_port is None:
        health_check_port = "N/A"
    if health_check_path is None:
        health_check_path = "N/A"

    row = [''] * len(Header)
    row[Header.index("Account ID")] = account_id
    row[Header.index("Region")] = region
    row[Header.index("Record Name")] = rec_name
    row[Header.index("Record Type")] = rec_type
    row[Header.index("TTL")] = ttl
    row[Header.index("Zone Type")] = zone_type
    row[Header.index("Load Balancer ARN")] = elb_arn
    row[Header.index("Listener ID")] = listener_id
    row[Header.index("Target Group Name")] = target_group_name
    row[Header.index("TLS")] = tls
    row[Header.index("HealthCheckEnabled")] = health_check_enabled
    row[Header.index("HealthCheckProtocol")] = health_check_protocol
    row[Header.index("HealthCheckPort")] = health_check_port
    row[Header.index("HealthCheckPath")] = health_check_path

    writer.writerow(row)

def get_zone_type(route53, hosted_zone_id):
    try:
        zone = route53.get_hosted_zone(Id=hosted_zone_id)['HostedZone']
        return 'private' if zone.get('Config', {}).get('PrivateZone') else 'public'
    except:
        Logger.debug(f"Can't find zone type for {hosted_zone_id}")
        return "public"