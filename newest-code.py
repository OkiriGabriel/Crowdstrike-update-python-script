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