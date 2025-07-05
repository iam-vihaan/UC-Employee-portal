# Terraform configuration for AWS infrastructure
terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.1"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = merge(var.tags, {
      Project     = "employee-directory"
      Environment = var.environment
      ManagedBy   = "terraform"
    })
  }
}

# Data sources
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

# Local values for common configurations
locals {
  name_prefix = "${var.cluster_name}-${var.environment}"
  
  common_tags = {
    Project     = "employee-directory"
    Environment = var.environment
    ManagedBy   = "terraform"
  }

  # Kubernetes cluster tags
  cluster_tags = {
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
  }
}
