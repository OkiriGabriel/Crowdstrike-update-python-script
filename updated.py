import boto3
import json
import logging
import time
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    # Set up AWS clients
    ssm = boto3.client('ssm')
    ec2 = boto3.client('ec2')
    
    # Configure variables
    aws_bucket = "crowdstrike-config"
    install_path = "Security/deploy/installs/Crowdstrike/"
    windows_installer = "WindowsSensor (2).exe"
    linux_installer = "falcon-sensor-7.17.0-17005.amzn2023.x86_64.rpm"
    environment = "sandbox"
    
    logger.info("Querying for running EC2 instances")
    # Query for running instances
    response = ec2.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
    instances = []
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            instances.append(instance['InstanceId'])
    logger.info(f"Found {len(instances)} running instances")

    for instance_id in instances:
        logger.info(f"Processing instance: {instance_id}")
        try:
            instance_info = ec2.describe_instances(InstanceIds=[instance_id])
            platform = instance_info['Reservations'][0]['Instances'][0].get('Platform')
            
            if platform == 'windows':
                command_type = 'powershell'
                installer = windows_installer
            else:
                command_type = 'bash'
                installer = linux_installer
            
            logger.info(f"Detected platform for {instance_id}: {'Windows' if platform == 'windows' else 'Linux'}")
            
        except Exception as e:
            logger.error(f"Error detecting platform for instance {instance_id}: {str(e)}")
            continue

        if platform == 'windows':
            command = f"""
            aws s3 cp s3://{aws_bucket}/{install_path}{installer} C:\\Windows\\Temp\\
            $CID = (aws ssm get-parameter --name /{environment}/shared/crowdstrike/checksum --query 'Parameter.Value' --with-decryption --output text)
            Start-Process -FilePath "C:\\Windows\\Temp\\{installer}" -ArgumentList "/install /quiet /norestart CID=$CID" -Wait
            Remove-Item -Path "C:\\Windows\\Temp\\{installer}" -Force
            Get-Service -Name CSFalconService | Select-Object Status
            """
        else:
            command = f"""
            aws s3 cp s3://{aws_bucket}/{install_path}{installer} /tmp/
            sudo yum install -y /tmp/{installer}
            rm -f /tmp/{installer}
            CID=$(aws ssm get-parameter --name /{environment}/shared/crowdstrike/checksum --query "Parameter.Value" --with-decryption --output text)
            sudo /opt/CrowdStrike/falconctl -s --cid=$CID
            sudo systemctl enable falcon-sensor
            sudo systemctl start falcon-sensor
            sudo /opt/CrowdStrike/falconctl -g --version
            ps -e | grep falcon-sensor || echo "The falcon-sensor is not running successfully! Please start the service"
            """

        send_command_with_retry(ssm, instance_id, command_type, command)

    return {
        'statusCode': 200,
        'body': json.dumps(f'CrowdStrike installation initiated on {len(instances)} instances.')
    }

def send_command_with_retry(ssm, instance_id, command_type, command, max_retries=5, initial_delay=30):
    for attempt in range(max_retries):
        try:
            response = ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName='AWS-RunShellScript' if command_type == 'bash' else 'AWS-RunPowerShellScript',
                Parameters={'commands': [command]},
            )
            command_id = response['Command']['CommandId']
            logger.info(f"SSM Command sent for instance {instance_id}. Command ID: {command_id}")
            return  # Success, exit the function
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidInstanceId':
                delay = initial_delay * (2 ** attempt)  # Exponential backoff
                logger.warning(f"Instance {instance_id} not ready. Retrying in {delay} seconds. Attempt {attempt + 1}/{max_retries}")
                time.sleep(delay)
            else:
                logger.error(f"Unexpected error sending SSM command for instance {instance_id}: {str(e)}")
                return  # Exit on unexpected errors
    
    logger.error(f"Failed to send SSM command to instance {instance_id} after {max_retries} attempts")