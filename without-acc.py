# import csv
# import io
# import boto3
# import logging

# # Configure logging
# logging.basicConfig(level=logging.INFO)
# Logger = logging.getLogger(__name__)

# Header = [
#     "Region",
#     "Record Name",
#     "Record Type",
#     "TTL",
#     "Zone Type",
#     "Hosted Zone ID",
#     "Load Balancer ARN",
#     "Listener ID",
#     "Target Group Name",
#     "TLS",
#     "HealthCheckEnabled",
#     "HealthCheckProtocol",
#     "HealthCheckPort",
#     "HealthCheckPath",
# ]

# def lambda_handler(event, context):
#     output = io.StringIO()
#     writer = csv.writer(output)
#     writer.writerow(Header)

#     process_account(writer)

#     # Get the CSV content as a string
#     csv_content = output.getvalue()
#     output.close()

#     # Save to S3
#     s3 = boto3.client('s3')
#     bucket_name = 'awsbucketew'  # Replace with your actual bucket name
#     file_name = 'dns_records.csv'
    
#     try:
#         s3.put_object(Bucket=bucket_name, Key=file_name, Body=csv_content)
#         return {
#             'statusCode': 200,
#             'body': f'CSV file successfully generated and saved to s3://{bucket_name}/{file_name}'
#         }
#     except Exception as e:
#         Logger.error(f"Error uploading to S3: {str(e)}")
#         return {
#             'statusCode': 500,
#             'body': f'Error uploading CSV file to S3: {str(e)}'
#         }

# def process_account(writer):
#     elbv2 = boto3.client('elbv2')
#     route53 = boto3.client('route53')

#     seen = {}
#     for elb in elbv2.describe_load_balancers()['LoadBalancers']:
#         Logger.debug(f"Processing ELB {elb['LoadBalancerArn']}")
#         if elb['Type'] in ['network', 'application']:
#             region = elb['AvailabilityZones'][0]['ZoneName'][:-1]  # Extracts region from AZ

#             dns_map = {}
#             for hosted_zone in route53.list_hosted_zones()['HostedZones']:
#                 records = route53.list_resource_record_sets(HostedZoneId=hosted_zone['Id'])['ResourceRecordSets']
#                 for record in records:
#                     if record['Name'] == elb['DNSName'] or ('AliasTarget' in record and record['AliasTarget']['DNSName'] == elb['DNSName']):
#                         dns_map[record['Name']] = {
#                             "rec_type": record['Type'],
#                             "zone_type": 'private' if hosted_zone.get('Config', {}).get('PrivateZone') else 'public',
#                             "hosted_zone_id": hosted_zone['Id'],
#                             "ttl": record.get('TTL', 'N/A')
#                         }

#             listeners = elbv2.describe_listeners(LoadBalancerArn=elb['LoadBalancerArn'])['Listeners']
#             for listener in listeners:
#                 target_group_arns = []
#                 rules = elbv2.describe_rules(ListenerArn=listener['ListenerArn'])['Rules']
#                 for rule in rules:
#                     for action in rule['Actions']:
#                         if 'TargetGroupArn' in action:
#                             target_group_arns.append(action['TargetGroupArn'])

#                 for target_group_arn in target_group_arns:
#                     target_group = elbv2.describe_target_groups(TargetGroupArns=[target_group_arn])['TargetGroups'][0]
#                     for rec_name, rec_info in dns_map.items():
#                         write_row(
#                             writer=writer,
#                             region=region,
#                             rec_name=rec_name,
#                             rec_type=rec_info["rec_type"],
#                             ttl=rec_info["ttl"],
#                             zone_type=rec_info["zone_type"],
#                             hosted_zone_id=rec_info["hosted_zone_id"],
#                             elb_arn=elb['LoadBalancerArn'],
#                             listener_id=listener['ListenerArn'].split('/')[-1],
#                             target_group_name=target_group['TargetGroupName'],
#                             tls=listener.get('SslPolicy', 'N/A'),
#                             health_check_enabled=target_group['HealthCheckEnabled'],
#                             health_check_protocol=target_group['HealthCheckProtocol'],
#                             health_check_port=target_group['HealthCheckPort'],
#                             health_check_path=target_group.get('HealthCheckPath', 'N/A'),
#                         )

#                         seen[rec_name] = True

#     Logger.debug("Processing non-ELB records")

#     for zone in route53.list_hosted_zones()['HostedZones']:
#         records = route53.list_resource_record_sets(HostedZoneId=zone['Id'])['ResourceRecordSets']
#         for rec in records:
#             Logger.debug(f"Processing record {rec['Name']}")
#             if rec['Name'] not in seen:
#                 if rec['Type'] in ["A", "CNAME"]:
#                     ttl = rec.get('TTL', 'N/A')
#                     write_row(
#                         writer=writer,
#                         region='N/A',  # Route 53 is a global service
#                         rec_name=rec['Name'],
#                         rec_type=rec['Type'],
#                         ttl=ttl,
#                         zone_type='private' if zone.get('Config', {}).get('PrivateZone') else 'public',
#                         hosted_zone_id=zone['Id'],
#                     )

# def write_row(
#     writer,
#     region,
#     rec_name,
#     rec_type,
#     ttl,
#     zone_type,
#     hosted_zone_id,
#     elb_arn=None,
#     listener_id=None,
#     target_group_name=None,
#     tls=None,
#     health_check_enabled=False,
#     health_check_protocol=None,
#     health_check_port=None,
#     health_check_path=None,
# ):
#     if elb_arn is None:
#         elb_arn = "N/A"
#     if listener_id is None:
#         listener_id = "N/A"
#     if target_group_name is None:
#         target_group_name = "N/A"
#     if tls is None:
#         tls = "N/A"
#     if health_check_enabled is None:
#         health_check_enabled = False
#     if health_check_protocol is None:
#         health_check_protocol = "N/A"
#     if health_check_port is None:
#         health_check_port = "N/A"
#     if health_check_path is None:
#         health_check_path = "N/A"

#     row = [''] * len(Header)
#     row[Header.index("Region")] = region
#     row[Header.index("Record Name")] = rec_name
#     row[Header.index("Record Type")] = rec_type
#     row[Header.index("TTL")] = ttl
#     row[Header.index("Zone Type")] = zone_type
#     row[Header.index("Hosted Zone ID")] = hosted_zone_id
#     row[Header.index("Load Balancer ARN")] = elb_arn
#     row[Header.index("Listener ID")] = listener_id
#     row[Header.index("Target Group Name")] = target_group_name
#     row[Header.index("TLS")] = tls
#     row[Header.index("HealthCheckEnabled")] = health_check_enabled
#     row[Header.index("HealthCheckProtocol")] = health_check_protocol
#     row[Header.index("HealthCheckPort")] = health_check_port
#     row[Header.index("HealthCheckPath")] = health_check_path

#     writer.writerow(row)



import csv
import boto3
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
Logger = logging.getLogger(__name__)

# Set your AWS account ID and region
AWS_ACCOUNT_ID = '147726474727'  # Replace with your AWS account ID
AWS_REGION = 'us-east-1'  # Replace with your desired region, e.g., 'us-east-1'

# S3 bucket details
S3_BUCKET_NAME = 'awsbucketew'  # Replace with your S3 bucket name
S3_FILE_NAME = 'dns_records.csv'

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
    # Create a CSV file
    with open(S3_FILE_NAME, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(Header)
        
        process_account(writer, AWS_ACCOUNT_ID, AWS_REGION)
    
    # Upload to S3
    upload_to_s3(S3_FILE_NAME, S3_BUCKET_NAME, S3_FILE_NAME)

def process_account(writer, account_id, region):
    # Create boto3 clients
    elbv2 = boto3.client('elbv2', region_name=region)
    route53 = boto3.client('route53', region_name=region)

    Logger.info(f"Processing account {account_id} in region {region}")

    seen = {}
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

def upload_to_s3(local_file, bucket, s3_file):
    s3 = boto3.client('s3')
    try:
        s3.upload_file(local_file, bucket, s3_file)
        Logger.info(f"Upload Successful: {local_file} to {bucket}/{s3_file}")
    except Exception as e:
        Logger.error(f"Error uploading to S3: {str(e)}")

if __name__ == "__main__":
    main()