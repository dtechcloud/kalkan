terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = "eu-central-1"
}

variable "vpc_id" {
  type        = string
  description = "VPC of the shop"
}

resource "aws_security_group" "bastion" {
  name        = "vulnapp-bastion"
  description = "SSH access to the bastion host"
  vpc_id      = var.vpc_id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "jump" {
  name        = "vulnapp-jump"
  description = "SSH access from the office network"
  vpc_id      = var.vpc_id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.20.0.0/16"]
  }
}

resource "aws_s3_bucket" "exports" {
  bucket = "vulnapp-exports"
}

resource "aws_s3_bucket_public_access_block" "exports" {
  bucket                  = aws_s3_bucket.exports.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_acl" "exports" {
  bucket = aws_s3_bucket.exports.id
  acl    = "public-read"
}

resource "aws_s3_bucket" "archive" {
  bucket = "vulnapp-archive"
}

resource "aws_s3_bucket_public_access_block" "archive" {
  bucket                  = aws_s3_bucket.archive.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_acl" "archive" {
  bucket = aws_s3_bucket.archive.id
  acl    = "private"
}

resource "aws_kms_key" "volumes" {
  description         = "Key for the shop volumes"
  enable_key_rotation = true
}

resource "aws_ebs_volume" "data" {
  availability_zone = "eu-central-1a"
  size              = 50
  encrypted         = false
}

resource "aws_ebs_volume" "logs" {
  availability_zone = "eu-central-1a"
  size              = 50
  encrypted         = true
  kms_key_id        = aws_kms_key.volumes.arn
}
