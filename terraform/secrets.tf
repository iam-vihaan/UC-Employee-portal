# Secrets Manager Module
# This module creates and manages secrets for the application

# KMS Key for Secrets Manager encryption
resource "aws_kms_key" "secrets" {
  description             = "KMS key for Secrets Manager encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow Secrets Manager to use the key"
        Effect = "Allow"
        Principal = {
          Service = "secretsmanager.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:ReEncrypt*"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-secrets-kms-key"
  })
}

resource "aws_kms_alias" "secrets" {
  name          = "alias/${local.name_prefix}-secrets"
  target_key_id = aws_kms_key.secrets.key_id
}

# Database Credentials Secret
resource "aws_secretsmanager_secret" "db_credentials" {
  name        = "${local.name_prefix}-db-credentials"
  description = "Database credentials for Employee Directory application"
  kms_key_id  = aws_kms_key.secrets.arn

  replica {
    region = var.aws_region
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-db-credentials"
  })
}

resource "aws_secretsmanager_secret_version" "db_credentials" {
  secret_id = aws_secretsmanager_secret.db_credentials.id
  secret_string = jsonencode({
    username = aws_db_instance.main.username
    password = aws_db_instance.main.password
    host     = aws_db_instance.main.endpoint
    port     = aws_db_instance.main.port
    dbname   = aws_db_instance.main.db_name
    engine   = "postgres"
    # Connection string for easy use
    database_url = "postgresql://${aws_db_instance.main.username}:${aws_db_instance.main.password}@${aws_db_instance.main.endpoint}:${aws_db_instance.main.port}/${aws_db_instance.main.db_name}"
  })

  lifecycle {
    ignore_changes = [secret_string]
  }
}

# JWT Secret
resource "aws_secretsmanager_secret" "jwt_secret" {
  name        = "${local.name_prefix}-jwt-secret"
  description = "JWT secret key for Employee Directory application"
  kms_key_id  = aws_kms_key.secrets.arn

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-jwt-secret"
  })
}

resource "random_password" "jwt_secret" {
  length  = 32
  special = true
}

resource "aws_secretsmanager_secret_version" "jwt_secret" {
  secret_id = aws_secretsmanager_secret.jwt_secret.id
  secret_string = jsonencode({
    jwt_secret_key = random_password.jwt_secret.result
  })
}

# Application Configuration Secret
resource "aws_secretsmanager_secret" "app_config" {
  name        = "${local.name_prefix}-app-config"
  description = "Application configuration for Employee Directory"
  kms_key_id  = aws_kms_key.secrets.arn

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-app-config"
  })
}

resource "aws_secretsmanager_secret_version" "app_config" {
  secret_id = aws_secretsmanager_secret.app_config.id
  secret_string = jsonencode({
    environment     = var.environment
    cluster_name    = var.cluster_name
    aws_region      = var.aws_region
    cors_origins    = "*"
    log_level       = var.environment == "production" ? "INFO" : "DEBUG"
    session_timeout = "3600"
  })
}

# Secret for External Services (if needed)
resource "aws_secretsmanager_secret" "external_services" {
  name        = "${local.name_prefix}-external-services"
  description = "External service credentials and API keys"
  kms_key_id  = aws_kms_key.secrets.arn

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-external-services"
  })
}

resource "aws_secretsmanager_secret_version" "external_services" {
  secret_id = aws_secretsmanager_secret.external_services.id
  secret_string = jsonencode({
    # Placeholder for external service credentials
    # Add actual credentials as needed
    smtp_host     = ""
    smtp_port     = "587"
    smtp_username = ""
    smtp_password = ""
    # Add other external service credentials here
  })
}

# Secret Rotation Configuration (for database credentials)
resource "aws_secretsmanager_secret_rotation" "db_credentials" {
  count = var.environment == "production" ? 1 : 0

  secret_id           = aws_secretsmanager_secret.db_credentials.id
  rotation_lambda_arn = aws_lambda_function.rotate_secret[0].arn

  rotation_rules {
    automatically_after_days = 30
  }

  depends_on = [aws_lambda_permission.allow_secret_manager_call_lambda]
}

# Lambda function for secret rotation (production only)
resource "aws_lambda_function" "rotate_secret" {
  count = var.environment == "production" ? 1 : 0

  filename         = "rotate_secret.zip"
  function_name    = "${local.name_prefix}-rotate-secret"
  role            = aws_iam_role.lambda_rotation[0].arn
  handler         = "lambda_function.lambda_handler"
  source_code_hash = data.archive_file.rotate_secret_zip[0].output_base64sha256
  runtime         = "python3.9"
  timeout         = 30

  environment {
    variables = {
      SECRETS_MANAGER_ENDPOINT = "https://secretsmanager.${var.aws_region}.amazonaws.com"
    }
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-rotate-secret"
  })
}

# Lambda deployment package
data "archive_file" "rotate_secret_zip" {
  count = var.environment == "production" ? 1 : 0

  type        = "zip"
  output_path = "rotate_secret.zip"
  source {
    content = templatefile("${path.module}/templates/rotate_secret.py", {
      region = var.aws_region
    })
    filename = "lambda_function.py"
  }
}

# IAM role for Lambda rotation function
resource "aws_iam_role" "lambda_rotation" {
  count = var.environment == "production" ? 1 : 0

  name = "${local.name_prefix}-lambda-rotation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "lambda_rotation" {
  count = var.environment == "production" ? 1 : 0

  name = "${local.name_prefix}-lambda-rotation-policy"
  role = aws_iam_role.lambda_rotation[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:DescribeSecret",
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
          "secretsmanager:UpdateSecretVersionStage"
        ]
        Resource = aws_secretsmanager_secret.db_credentials.arn
      },
      {
        Effect = "Allow"
        Action = [
          "rds:ModifyDBInstance"
        ]
        Resource = aws_db_instance.main.arn
      }
    ]
  })
}

resource "aws_lambda_permission" "allow_secret_manager_call_lambda" {
  count = var.environment == "production" ? 1 : 0

  statement_id  = "AllowExecutionFromSecretsManager"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.rotate_secret[0].function_name
  principal     = "secretsmanager.amazonaws.com"
}
