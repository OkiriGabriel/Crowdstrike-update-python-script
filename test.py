import boto3
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    instance_id = event['detail']['instance-id']
    
    ssm = boto3.client('ssm')
    ec2 = boto3.client('ec2')

    aws_bucket = "crowdstrike-config"
    install_path = "Security/deploy/installs/Crowdstrike/"
    windows_installer = "WindowsSensor (2).exe"
    linux_installer = "falcon-sensor-7.17.0-17005.amzn2023.x86_64.rpm"
    environment = "sandbox"
    
    logger.info(f"Initiating CrowdStrike installation on instance {instance_id}")

    try:
        instance_info = ec2.describe_instances(InstanceIds=[instance_id])
        platform = instance_info['Reservations'][0]['Instances'][0].get('Platform')
        
        if platform == 'windows':
            command_type = 'powershell'
            installer = windows_installer
        else:
            command_type = 'bash'
            installer = linux_installer
        
        logger.info(f"Detected platform: {'Windows' if platform == 'windows' else 'Linux'}")
    except Exception as e:
        logger.error(f"Error detecting instance platform: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps('Error: Failed to detect instance platform')
        }

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

    try:
        response = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName='AWS-RunShellScript' if command_type == 'bash' else 'AWS-RunPowerShellScript',
            Parameters={'commands': [command]},
        )
        command_id = response['Command']['CommandId']
        logger.info(f"SSM Command sent. Command ID: {command_id}")
    except Exception as e:
        logger.error(f"Error sending SSM command: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps('Error: Failed to send SSM command')
        }

    return {
        'statusCode': 200,
        'body': json.dumps(f'CrowdStrike installation initiated on instance {instance_id}')
    }
    
 
    