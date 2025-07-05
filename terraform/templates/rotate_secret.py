import boto3
import json
import logging
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    Lambda function to rotate RDS database credentials
    """
    service = boto3.client('secretsmanager', region_name='${region}')
    rds = boto3.client('rds', region_name='${region}')
    
    arn = event['Step']
    token = event['ClientRequestToken']
    step = event['Step']
    
    # Get the secret
    metadata = service.describe_secret(SecretId=arn)
    versions = metadata["VersionIdsToStages"]
    
    if 'AWSCURRENT' not in versions:
        logger.error("Secret %s has no AWSCURRENT version", arn)
        raise ValueError("Secret %s has no AWSCURRENT version" % arn)
    
    # Call the appropriate step function
    if step == "createSecret":
        create_secret(service, arn, token)
    elif step == "setSecret":
        set_secret(service, rds, arn, token)
    elif step == "testSecret":
        test_secret(service, arn, token)
    elif step == "finishSecret":
        finish_secret(service, arn, token)
    else:
        logger.error("Invalid step parameter %s", step)
        raise ValueError("Invalid step parameter %s" % step)

def create_secret(service, arn, token):
    """
    Create a new secret version with a new password
    """
    try:
        service.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        logger.info("createSecret: Successfully retrieved secret for %s.", arn)
    except service.exceptions.ResourceNotFoundException:
        # Generate a new password
        current_secret = service.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")
        secret_dict = json.loads(current_secret['SecretString'])
        
        # Generate new password
        new_password = service.get_random_password(
            PasswordLength=16,
            ExcludeCharacters='"@/\\'
        )['RandomPassword']
        
        secret_dict['password'] = new_password
        
        # Put the new secret
        service.put_secret_value(
            SecretId=arn,
            ClientRequestToken=token,
            SecretString=json.dumps(secret_dict),
            VersionStages=['AWSPENDING']
        )
        logger.info("createSecret: Successfully put secret for ARN %s and version %s.", arn, token)

def set_secret(service, rds, arn, token):
    """
    Set the secret in the database
    """
    pending_secret = service.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
    secret_dict = json.loads(pending_secret['SecretString'])
    
    # Update the database password
    try:
        rds.modify_db_instance(
            DBInstanceIdentifier=secret_dict['dbInstanceIdentifier'],
            MasterUserPassword=secret_dict['password'],
            ApplyImmediately=True
        )
        logger.info("setSecret: Successfully set password for %s", secret_dict['dbInstanceIdentifier'])
    except Exception as e:
        logger.error("setSecret: Failed to set password for %s: %s", secret_dict['dbInstanceIdentifier'], str(e))
        raise e

def test_secret(service, arn, token):
    """
    Test the new secret
    """
    # For this implementation, we'll just verify the secret exists
    try:
        service.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        logger.info("testSecret: Successfully tested secret for %s", arn)
    except Exception as e:
        logger.error("testSecret: Failed to test secret for %s: %s", arn, str(e))
        raise e

def finish_secret(service, arn, token):
    """
    Finish the rotation by updating the version stages
    """
    metadata = service.describe_secret(SecretId=arn)
    current_version = None
    
    for version in metadata["VersionIdsToStages"]:
        if "AWSCURRENT" in metadata["VersionIdsToStages"][version]:
            if version == token:
                logger.info("finishSecret: Version %s already marked as AWSCURRENT for %s", version, arn)
                return
            current_version = version
            break
    
    # Update version stages
    service.update_secret_version_stage(
        SecretId=arn,
        VersionStage="AWSCURRENT",
        ClientRequestToken=token,
        RemoveFromVersionId=current_version
    )
    logger.info("finishSecret: Successfully set AWSCURRENT stage to version %s for secret %s.", token, arn)
