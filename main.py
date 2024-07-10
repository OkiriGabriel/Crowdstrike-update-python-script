import boto3
import subprocess
import os

def lambda_handler(event, context):
    # This will extract the server ID from the cloudwatch event
    instance_id = event['detail']['instance-id']
    
    # AWS clIENT
    ec2 = boto3.client('ec2')
    ssm = boto3.client('ssm')
    s3 = boto3.client('s3')

    # Variables
    aws_bucket = "paytrace-devops"
    environment = "prod"

    # Get the latest Falcon sensor filename
    s3_objects = s3.list_objects_v2(Bucket=aws_bucket, Prefix="devops/deploy/installs/Crowdstrike/")
    falcon_sensor_filename = sorted([obj['Key'] for obj in s3_objects['Contents'] if obj['Key'].endswith('.deb')])[-1].split('/')[-1]

    # Get CrowdStrike CID from SSM Parameter Store
    cid = ssm.get_parameter(Name=f'/{environment}/shared/crowdstrike/checksum', WithDecryption=True)['Parameter']['Value']

    # Prepare the installation script
    install_script = f"""
    #!/bin/bash
    aws s3 cp s3://{aws_bucket}/devops/deploy/installs/Crowdstrike/{falcon_sensor_filename} /tmp/
    sudo dpkg -i /tmp/{falcon_sensor_filename}
    rm /tmp/{falcon_sensor_filename}
    sudo /opt/CrowdStrike/falconctl -s --cid={cid}
    sudo systemctl enable falcon-sensor
    sudo systemctl start falcon-sensor
    sudo /opt/CrowdStrike/falconctl -g --version
    ps -e | grep falcon-sensor || echo "The falcon-sensor is not running successfully! Please start the service"
    """

    # Run the installation script on the EC2 instance using SSM Run Command
    response = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName='AWS-RunShellScript',
        Parameters={'commands': [install_script]}
    )

    return {
        'statusCode': 200,
        'body': f'CrowdStrike installation initiated on instance {instance_id}'
    }