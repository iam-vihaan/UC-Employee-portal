# RDS Module - Database Infrastructure
# This module creates RDS PostgreSQL instance with proper security and backup configuration

# Random password for database
resource "random_password" "db_password" {
  length  = 16
  special = true
}

# RDS Subnet Group
resource "aws_db_subnet_group" "main" {
  name       = "${local.name_prefix}-db-subnet-group"
  subnet_ids = aws_subnet.database[*].id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-db-subnet-group"
  })
}

# RDS Parameter Group
resource "aws_db_parameter_group" "main" {

  family = "postgres14"

  name   = "${local.name_prefix}-db-params"

  parameter {

    name         = "log_statement"

    value        = "all"

    apply_method = "immediate"

  }

  parameter {

    name         = "log_min_duration_statement"

    value        = "1000"

    apply_method = "immediate"

  }

  parameter {

    name         = "log_connections"

    value        = "1"

    apply_method = "immediate"

  }

  parameter {

    name         = "log_disconnections"

    value        = "1"

    apply_method = "immediate"

  }

  parameter {

    name         = "shared_preload_libraries"

    value        = "pg_stat_statements"

    apply_method = "pending-reboot" # static parameter

  }

  parameter {

    name         = "max_connections"

    value        = "200"

    apply_method = "pending-reboot" # typically static

  }

  tags = merge(local.common_tags, {

    Name = "${local.name_prefix}-db-params"

  })

}

# RDS Option Group (for PostgreSQL, this is minimal)
resource "aws_db_option_group" "main" {
  name                 = "${local.name_prefix}-db-options"
  option_group_description = "Option group for ${local.name_prefix} PostgreSQL"
  engine_name          = "postgres"
  major_engine_version = "14"

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-db-options"
  })
}

# KMS Key for RDS encryption
resource "aws_kms_key" "rds" {
  description             = "KMS key for RDS encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-rds-kms-key"
  })
}

resource "aws_kms_alias" "rds" {
  name          = "alias/${local.name_prefix}-rds"
  target_key_id = aws_kms_key.rds.key_id
}

# RDS Instance
resource "aws_db_instance" "main" {
  identifier = "${local.name_prefix}-database"

  # Engine configuration
  engine         = "postgres"
  engine_version = "14.9"
  instance_class = var.db_instance_class

  # Storage configuration
  allocated_storage     = var.db_allocated_storage
  max_allocated_storage = var.db_max_allocated_storage
  storage_type          = "gp3"
  storage_encrypted     = var.enable_encryption
  kms_key_id           = var.enable_encryption ? aws_kms_key.rds.arn : null

  # Database configuration
  db_name  = var.db_name
  username = var.db_username
  password = random_password.db_password.result

  # Network configuration
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  publicly_accessible    = false
  port                   = 5432

  # Backup configuration
  backup_retention_period   = var.db_backup_retention_period
  backup_window            = "03:00-04:00"
  maintenance_window       = "sun:04:00-sun:05:00"
  copy_tags_to_snapshot    = true
  delete_automated_backups = false

  # High availability
  multi_az = var.db_multi_az

  # Monitoring
  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_monitoring.arn
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  # Performance Insights
  performance_insights_enabled          = true
  performance_insights_retention_period = 7
  performance_insights_kms_key_id      = var.enable_encryption ? aws_kms_key.rds.arn : null

  # Parameter and option groups
  parameter_group_name = aws_db_parameter_group.main.name
  option_group_name    = aws_db_option_group.main.name

  # Deletion protection
  deletion_protection = var.enable_deletion_protection
  skip_final_snapshot = !var.enable_deletion_protection

  # Final snapshot identifier
  final_snapshot_identifier = var.enable_deletion_protection ? "${local.name_prefix}-final-snapshot-${formatdate("YYYY-MM-DD-hhmm", timestamp())}" : null

  # Auto minor version upgrade
  auto_minor_version_upgrade = true

  # Apply changes immediately (for non-production environments)
  apply_immediately = var.environment != "production"

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-database"
  })

  lifecycle {
    ignore_changes = [
      password,
      final_snapshot_identifier,
    ]
  }
}

# RDS Monitoring Role
resource "aws_iam_role" "rds_monitoring" {
  name = "${local.name_prefix}-rds-monitoring-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-rds-monitoring-role"
  })
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# CloudWatch Log Groups for RDS
resource "aws_cloudwatch_log_group" "rds_postgresql" {
  name              = "/aws/rds/instance/${aws_db_instance.main.identifier}/postgresql"
  retention_in_days = var.log_retention_days

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-rds-postgresql-logs"
  })
}

resource "aws_cloudwatch_log_group" "rds_upgrade" {
  name              = "/aws/rds/instance/${aws_db_instance.main.identifier}/upgrade"
  retention_in_days = var.log_retention_days

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-rds-upgrade-logs"
  })
}

# RDS Subnet Group for read replicas (if needed in the future)
resource "aws_db_subnet_group" "replica" {
  name       = "${local.name_prefix}-replica-subnet-group"
  subnet_ids = aws_subnet.database[*].id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-replica-subnet-group"
  })
}
