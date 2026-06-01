# ============================================================================
# Terraform — Multi-VPC, Security Groups, NACLs, WAF v2, Shield Advanced
# Production-grade security posture for FPM knowledge base.
# ============================================================================

# ---------- Provider ----------

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# ============================================================================
# VPC — Production (primary workloads)
# ============================================================================

resource "aws_vpc" "prod" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "prod-vpc" }
}

resource "aws_subnet" "public_a" {
  vpc_id            = aws_vpc.prod.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"
  tags = { Name = "public-subnet-a" }
}

resource "aws_subnet" "public_b" {
  vpc_id            = aws_vpc.prod.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1b"
  tags = { Name = "public-subnet-b" }
}

resource "aws_subnet" "private_app_a" {
  vpc_id            = aws_vpc.prod.id
  cidr_block        = "10.0.10.0/24"
  availability_zone = "us-east-1a"
  tags = { Name = "private-app-subnet-a" }
}

resource "aws_subnet" "private_app_b" {
  vpc_id            = aws_vpc.prod.id
  cidr_block        = "10.0.11.0/24"
  availability_zone = "us-east-1b"
  tags = { Name = "private-app-subnet-b" }
}

resource "aws_subnet" "private_data_a" {
  vpc_id            = aws_vpc.prod.id
  cidr_block        = "10.0.20.0/24"
  availability_zone = "us-east-1a"
  tags = { Name = "private-data-subnet-a" }
}

resource "aws_subnet" "private_data_b" {
  vpc_id            = aws_vpc.prod.id
  cidr_block        = "10.0.21.0/24"
  availability_zone = "us-east-1b"
  tags = { Name = "private-data-subnet-b" }
}

# ============================================================================
# VPC — Management (bastion, monitoring, CI/CD)
# ============================================================================

resource "aws_vpc" "management" {
  cidr_block           = "10.1.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "management-vpc" }
}

resource "aws_subnet" "mgmt_private_a" {
  vpc_id            = aws_vpc.management.id
  cidr_block        = "10.1.10.0/24"
  availability_zone = "us-east-1a"
  tags = { Name = "mgmt-private-subnet-a" }
}

# ============================================================================
# Transit Gateway — connects prod and management VPCs
# ============================================================================

resource "aws_ec2_transit_gateway" "main" {
  description                     = "Connects prod and management VPCs"
  default_route_table_association = "enable"
  default_route_table_propagation = "enable"
  dns_support                     = "enable"

  tags = { Name = "main-transit-gateway" }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "prod" {
  transit_gateway_id = aws_ec2_transit_gateway.main.id
  vpc_id             = aws_vpc.prod.id
  subnet_ids         = [aws_subnet.private_app_a.id, aws_subnet.private_app_b.id]

  tags = { Name = "prod-tgw-attachment" }
}

resource "aws_ec2_transit_gateway_vpc_attachment" "management" {
  transit_gateway_id = aws_ec2_transit_gateway.main.id
  vpc_id             = aws_vpc.management.id
  subnet_ids         = [aws_subnet.mgmt_private_a.id]

  tags = { Name = "mgmt-tgw-attachment" }
}

# ============================================================================
# VPC Endpoints — private access to AWS services (no internet needed)
# ============================================================================

resource "aws_vpc_endpoint" "s3" {
  vpc_id       = aws_vpc.prod.id
  service_name = "com.amazonaws.us-east-1.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private_app.id]

  tags = { Name = "s3-vpc-endpoint" }
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id       = aws_vpc.prod.id
  service_name = "com.amazonaws.us-east-1.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private_app.id]

  tags = { Name = "dynamodb-vpc-endpoint" }
}

resource "aws_vpc_endpoint" "secrets_manager" {
  vpc_id              = aws_vpc.prod.id
  service_name        = "com.amazonaws.us-east-1.secretsmanager"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private_app_a.id, aws_subnet.private_app_b.id]
  security_group_ids  = [aws_security_group.vpc_endpoints_sg.id]
  private_dns_enabled = true

  tags = { Name = "secrets-manager-vpc-endpoint" }
}

resource "aws_route_table" "private_app" {
  vpc_id = aws_vpc.prod.id
  tags   = { Name = "private-app-rt" }
}

# ============================================================================
# Security Groups
# ============================================================================

# ---------- ALB Security Group ----------
# Public-facing Application Load Balancer — allows inbound 443/80 from 0.0.0.0/0 only.

resource "aws_security_group" "alb_sg" {
  name        = "alb-public-sg"
  description = "Public ALB - allows inbound HTTPS/HTTP from anywhere"
  vpc_id      = aws_vpc.prod.id

  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP from internet (redirect to HTTPS)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "alb-public-sg" }
}

# ---------- Kong Gateway Security Group ----------
# Receives traffic from ALB only, forwards to internal services.

resource "aws_security_group" "kong_sg" {
  name        = "kong-gateway-sg"
  description = "Kong Gateway - receives from ALB, forwards to microservices"
  vpc_id      = aws_vpc.prod.id

  ingress {
    description     = "HTTP from ALB"
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  ingress {
    description     = "HTTPS from ALB"
    from_port       = 8443
    to_port         = 8443
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  ingress {
    description     = "gRPC from ALB"
    from_port       = 9080
    to_port         = 9080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  ingress {
    description = "Admin API from management VPC only"
    from_port   = 8001
    to_port     = 8001
    protocol    = "tcp"
    cidr_blocks = ["10.1.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "kong-gateway-sg" }
}

# ---------- Internal Microservices Security Group ----------
# Allows inbound ONLY from Kong Gateway SG, on ports 8080-8090.

resource "aws_security_group" "microservices_sg" {
  name        = "internal-microservices-sg"
  description = "Internal microservices - inbound only from Kong Gateway"
  vpc_id      = aws_vpc.prod.id

  ingress {
    description     = "Service traffic from Kong Gateway"
    from_port       = 8080
    to_port         = 8090
    protocol        = "tcp"
    security_groups = [aws_security_group.kong_sg.id]
  }

  ingress {
    description     = "gRPC traffic from Kong Gateway"
    from_port       = 50051
    to_port         = 50059
    protocol        = "tcp"
    security_groups = [aws_security_group.kong_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "internal-microservices-sg" }
}

# ---------- Database Security Group ----------
# RDS/Aurora — only accessible from microservices SG, not from Kong or ALB.

resource "aws_security_group" "database_sg" {
  name        = "database-sg"
  description = "Database tier - inbound only from microservices, not from gateway or public"
  vpc_id      = aws_vpc.prod.id

  ingress {
    description     = "PostgreSQL from microservices only"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.microservices_sg.id]
  }

  ingress {
    description     = "MySQL from microservices only"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.microservices_sg.id]
  }

  # No internet egress — database should not initiate outbound connections
  egress {
    description = "DNS resolution only"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  tags = { Name = "database-sg" }
}

# ---------- Redis/ElastiCache Security Group ----------
# Session storage and caching — only accessible from microservices SG.

resource "aws_security_group" "redis_sg" {
  name        = "redis-cache-sg"
  description = "Redis/ElastiCache - session storage, accessible only from microservices"
  vpc_id      = aws_vpc.prod.id

  ingress {
    description     = "Redis from microservices"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.microservices_sg.id]
  }

  # No internet egress
  egress {
    description = "VPC internal only"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/16"]
  }

  tags = { Name = "redis-cache-sg" }
}

# ---------- Fetch Service Security Group ----------
# Allows egress to partner CIDR only — blocks internal CIDR to prevent SSRF pivot.

resource "aws_security_group" "fetch_service_sg" {
  name        = "fetch-service-sg"
  description = "Fetch service - egress restricted to partner CIDR only, blocks internal"
  vpc_id      = aws_vpc.prod.id

  ingress {
    description     = "Traffic from Kong Gateway"
    from_port       = 8085
    to_port         = 8085
    protocol        = "tcp"
    security_groups = [aws_security_group.kong_sg.id]
  }

  # Allow egress ONLY to partner CIDR — NOT to internal VPC or metadata
  egress {
    description = "Egress to partner API only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["203.0.114.0/24"]  # partner CIDR
  }

  # Explicit: AWS SGs are allow-only, so the restricted egress above implicitly
  # blocks 10.0.0.0/16 and 169.254.169.254/32 since they are not listed.

  tags = { Name = "fetch-service-sg" }
}

# ---------- Bastion Host Security Group ----------
# Management access from known corporate IPs only.

resource "aws_security_group" "bastion_sg" {
  name        = "bastion-host-sg"
  description = "Bastion host - SSH from corporate VPN only"
  vpc_id      = aws_vpc.management.id

  ingress {
    description = "SSH from corporate VPN"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["198.51.100.0/28"]  # corporate VPN range
  }

  egress {
    description = "Access to prod VPC via transit gateway"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/16"]
  }

  tags = { Name = "bastion-host-sg" }
}

# ---------- VPC Endpoints Security Group ----------
# Allows HTTPS access to AWS service endpoints from within the VPC.

resource "aws_security_group" "vpc_endpoints_sg" {
  name        = "vpc-endpoints-sg"
  description = "VPC interface endpoints - HTTPS from VPC CIDR"
  vpc_id      = aws_vpc.prod.id

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  tags = { Name = "vpc-endpoints-sg" }
}

# ---------- GraphQL Service Security Group ----------
# Dedicated SG for the GraphQL service — only from Kong, restricted ports.

resource "aws_security_group" "graphql_sg" {
  name        = "graphql-service-sg"
  description = "GraphQL service - inbound only from Kong Gateway on port 8095"
  vpc_id      = aws_vpc.prod.id

  ingress {
    description     = "GraphQL from Kong Gateway"
    from_port       = 8095
    to_port         = 8095
    protocol        = "tcp"
    security_groups = [aws_security_group.kong_sg.id]
  }

  egress {
    description     = "Database access"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.database_sg.id]
  }

  egress {
    description     = "Redis cache access"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.redis_sg.id]
  }

  tags = { Name = "graphql-service-sg" }
}

# ---------- Webhook Receiver Security Group ----------
# Accepts inbound from specific partner IPs only (for webhook callbacks).

resource "aws_security_group" "webhook_sg" {
  name        = "webhook-receiver-sg"
  description = "Webhook receiver - inbound from known partner IPs and payment providers only"
  vpc_id      = aws_vpc.prod.id

  ingress {
    description = "Stripe webhook IPs"
    from_port   = 8096
    to_port     = 8096
    protocol    = "tcp"
    cidr_blocks = ["3.18.12.63/32", "3.130.192.231/32", "13.235.14.237/32"]
  }

  ingress {
    description = "Partner B2B webhook"
    from_port   = 8096
    to_port     = 8096
    protocol    = "tcp"
    cidr_blocks = ["203.0.114.0/24"]
  }

  ingress {
    description     = "Internal from Kong Gateway"
    from_port       = 8096
    to_port         = 8096
    protocol        = "tcp"
    security_groups = [aws_security_group.kong_sg.id]
  }

  egress {
    description     = "Queue and DB access"
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["10.0.0.0/16"]
  }

  tags = { Name = "webhook-receiver-sg" }
}

# ---------- NEW: Payment Service Security Group ----------
# Payment processing — strict egress to payment processor CIDRs only.

resource "aws_security_group" "payment_sg" {
  name        = "payment-service-sg"
  description = "Payment service - strict egress to Stripe/processor IPs only, PCI-DSS compliant"
  vpc_id      = aws_vpc.prod.id

  ingress {
    description     = "From Kong Gateway only"
    from_port       = 8097
    to_port         = 8097
    protocol        = "tcp"
    security_groups = [aws_security_group.kong_sg.id]
  }

  # PCI-DSS: egress restricted to payment processors only
  egress {
    description = "Stripe API"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["3.18.12.0/24", "3.130.192.0/24"]
  }

  egress {
    description = "Internal DB for transaction records"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    security_groups = [aws_security_group.database_sg.id]
  }

  tags = { Name = "payment-service-sg" }
}

# ============================================================================
# NACLs — Network-level stateless filtering
# ============================================================================

# ---------- Internal App Subnets NACL ----------

resource "aws_network_acl" "internal_app_nacl" {
  vpc_id     = aws_vpc.prod.id
  subnet_ids = [aws_subnet.private_app_a.id, aws_subnet.private_app_b.id]

  # Allow inbound from VPC only on service ports
  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "10.0.0.0/16"
    from_port  = 8080
    to_port    = 8099
  }

  # Allow inbound from management VPC (via transit gateway) for SSH/monitoring
  ingress {
    protocol   = "tcp"
    rule_no    = 110
    action     = "allow"
    cidr_block = "10.1.0.0/16"
    from_port  = 22
    to_port    = 22
  }

  # Allow gRPC inbound from VPC
  ingress {
    protocol   = "tcp"
    rule_no    = 120
    action     = "allow"
    cidr_block = "10.0.0.0/16"
    from_port  = 50051
    to_port    = 50059
  }

  # Allow ephemeral return traffic
  ingress {
    protocol   = "tcp"
    rule_no    = 900
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  # Deny all other inbound from internet
  ingress {
    protocol   = "tcp"
    rule_no    = 999
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 65535
  }

  # Allow outbound to VPC
  egress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "10.0.0.0/16"
    from_port  = 0
    to_port    = 65535
  }

  # Allow outbound HTTPS for AWS API calls (via VPC endpoints or NAT)
  egress {
    protocol   = "tcp"
    rule_no    = 200
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }

  tags = { Name = "internal-app-nacl" }
}

# ---------- Data Tier NACL ----------
# Strictest rules: only database ports from app subnets.

resource "aws_network_acl" "data_tier_nacl" {
  vpc_id     = aws_vpc.prod.id
  subnet_ids = [aws_subnet.private_data_a.id, aws_subnet.private_data_b.id]

  # PostgreSQL from app subnets only
  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "10.0.10.0/24"
    from_port  = 5432
    to_port    = 5432
  }

  ingress {
    protocol   = "tcp"
    rule_no    = 101
    action     = "allow"
    cidr_block = "10.0.11.0/24"
    from_port  = 5432
    to_port    = 5432
  }

  # MySQL from app subnets only
  ingress {
    protocol   = "tcp"
    rule_no    = 110
    action     = "allow"
    cidr_block = "10.0.10.0/24"
    from_port  = 3306
    to_port    = 3306
  }

  ingress {
    protocol   = "tcp"
    rule_no    = 111
    action     = "allow"
    cidr_block = "10.0.11.0/24"
    from_port  = 3306
    to_port    = 3306
  }

  # Redis from app subnets only
  ingress {
    protocol   = "tcp"
    rule_no    = 120
    action     = "allow"
    cidr_block = "10.0.10.0/24"
    from_port  = 6379
    to_port    = 6379
  }

  ingress {
    protocol   = "tcp"
    rule_no    = 121
    action     = "allow"
    cidr_block = "10.0.11.0/24"
    from_port  = 6379
    to_port    = 6379
  }

  # Deny everything else
  ingress {
    protocol   = "-1"
    rule_no    = 999
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  # Return traffic to app subnets only
  egress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "10.0.10.0/24"
    from_port  = 1024
    to_port    = 65535
  }

  egress {
    protocol   = "tcp"
    rule_no    = 101
    action     = "allow"
    cidr_block = "10.0.11.0/24"
    from_port  = 1024
    to_port    = 65535
  }

  # Deny all other egress (no internet, no other VPC access)
  egress {
    protocol   = "-1"
    rule_no    = 999
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = { Name = "data-tier-nacl" }
}

# ============================================================================
# WAF v2 — Advanced Web ACL with multiple managed rule groups
# ============================================================================

resource "aws_wafv2_ip_set" "blocked_ips" {
  name               = "blocked-ip-set"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"

  addresses = [
    "203.0.113.0/24",   # known botnet range
    "192.0.2.0/24",     # test/documentation range (suspicious in prod)
  ]

  tags = { Name = "blocked-ip-set" }
}

resource "aws_wafv2_ip_set" "geo_blocked_ips" {
  name               = "geo-blocked-ip-set"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"

  # IPs from sanctioned/high-risk regions (maintained by threat intel team)
  addresses = [
    "45.227.0.0/16",
    "91.234.0.0/16",
  ]

  tags = { Name = "geo-blocked-ip-set" }
}

resource "aws_wafv2_regex_pattern_set" "suspicious_ua" {
  name  = "suspicious-user-agents"
  scope = "REGIONAL"

  regular_expression {
    regex_string = "(?i)(sqlmap|nikto|nessus|masscan|zgrab|dirbuster|gobuster|wfuzz|hydra|medusa)"
  }

  regular_expression {
    regex_string = "(?i)(python-requests|go-http-client|java/|curl/|wget/)"
  }

  tags = { Name = "suspicious-user-agents" }
}

resource "aws_wafv2_web_acl" "api_waf" {
  name        = "api-waf-acl-v2"
  description = "Production WAF ACL — multi-layer protection with managed and custom rules"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  # ── Rule 1: IP Reputation Block ──
  rule {
    name     = "block-known-bad-ips"
    priority = 1

    action {
      block {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.blocked_ips.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "blocked-ips"
      sampled_requests_enabled   = true
    }
  }

  # ── Rule 2: Geo-restriction — block high-risk countries ──
  rule {
    name     = "geo-block-high-risk"
    priority = 2

    action {
      block {}
    }

    statement {
      geo_match_statement {
        country_codes = ["RU", "CN", "KP", "IR"]
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "geo-blocked"
      sampled_requests_enabled   = true
    }
  }

  # ── Rule 3: Suspicious User-Agent block ──
  rule {
    name     = "block-suspicious-user-agents"
    priority = 3

    action {
      block {}
    }

    statement {
      regex_pattern_set_reference_statement {
        arn = aws_wafv2_regex_pattern_set.suspicious_ua.arn
        field_to_match {
          single_header {
            name = "user-agent"
          }
        }
        text_transformation {
          priority = 0
          type     = "LOWERCASE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "suspicious-ua"
      sampled_requests_enabled   = true
    }
  }

  # ── Rule 4: Global rate limit — 2000 requests per 5 minutes per IP ──
  rule {
    name     = "global-rate-limit"
    priority = 4

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "global-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  # ── Rule 5: Login endpoint rate limit — 100 requests per 5 minutes per IP ──
  rule {
    name     = "login-rate-limit"
    priority = 5

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 100
        aggregate_key_type = "IP"

        scope_down_statement {
          byte_match_statement {
            search_string = "/api/v1/login"
            field_to_match {
              uri_path {}
            }
            positional_constraint = "STARTS_WITH"
            text_transformation {
              priority = 0
              type     = "LOWERCASE"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "login-rate-limit"
      sampled_requests_enabled   = true
    }
  }

  # ── Rule 6: AWS Managed — Common Rule Set ──
  rule {
    name     = "aws-common-rules"
    priority = 10

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "aws-common-rules"
      sampled_requests_enabled   = true
    }
  }

  # ── Rule 7: AWS Managed — SQL Injection ──
  rule {
    name     = "aws-sqli-rules"
    priority = 11

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "aws-sqli-rules"
      sampled_requests_enabled   = true
    }
  }

  # ── Rule 8: AWS Managed — Known Bad Inputs ──
  rule {
    name     = "aws-known-bad-inputs"
    priority = 12

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "aws-known-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  # ── Rule 9: AWS Managed — Bot Control ──
  rule {
    name     = "aws-bot-control"
    priority = 13

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesBotControlRuleSet"
        vendor_name = "AWS"

        managed_rule_group_configs {
          aws_managed_rules_bot_control_rule_set {
            inspection_level = "TARGETED"
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "aws-bot-control"
      sampled_requests_enabled   = true
    }
  }

  # ── Rule 10: AWS Managed — Anonymous IP List ──
  rule {
    name     = "aws-anonymous-ip"
    priority = 14

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAnonymousIpList"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "aws-anonymous-ip"
      sampled_requests_enabled   = true
    }
  }

  # ── Rule 11: AWS Managed — Linux OS rules ──
  rule {
    name     = "aws-linux-rules"
    priority = 15

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesLinuxRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "aws-linux-rules"
      sampled_requests_enabled   = true
    }
  }

  # ── Rule 12: Request body size constraint — 10MB max ──
  rule {
    name     = "body-size-limit"
    priority = 20

    action {
      block {}
    }

    statement {
      size_constraint_statement {
        comparison_operator = "GT"
        size                = 10485760
        field_to_match {
          body {
            oversize_handling = "MATCH"
          }
        }
        text_transformation {
          priority = 0
          type     = "NONE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "body-size-limit"
      sampled_requests_enabled   = true
    }
  }

  # ── Rule 13: Block requests with no User-Agent (bot indicator) ──
  rule {
    name     = "require-user-agent"
    priority = 21

    action {
      block {}
    }

    statement {
      size_constraint_statement {
        comparison_operator = "EQ"
        size                = 0
        field_to_match {
          single_header {
            name = "user-agent"
          }
        }
        text_transformation {
          priority = 0
          type     = "NONE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "no-user-agent"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "api-waf-acl-v2"
    sampled_requests_enabled   = true
  }

  tags = { Name = "api-waf-acl-v2" }
}

# ============================================================================
# Shield Advanced — DDoS protection on ALB
# ============================================================================

resource "aws_shield_protection" "alb_shield" {
  name         = "alb-ddos-protection"
  resource_arn = aws_lb.api_alb.arn

  tags = { Name = "alb-shield-protection" }
}

# ============================================================================
# ALB
# ============================================================================

resource "aws_lb" "api_alb" {
  name               = "api-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = [aws_subnet.public_a.id, aws_subnet.public_b.id]

  drop_invalid_header_fields = true

  tags = { Name = "api-alb" }
}

# Associate WAF with ALB
resource "aws_wafv2_web_acl_association" "alb_waf" {
  resource_arn = aws_lb.api_alb.arn
  web_acl_arn  = aws_wafv2_web_acl.api_waf.arn
}

# ============================================================================
# TRUE POSITIVE: Misconfigured Analytics Service Security Group
# ============================================================================
# A new analytics service was deployed but the SG was cloned from the
# ALB public SG instead of the internal microservices SG. This means
# the service is directly accessible from the internet on port 8098,
# bypassing Kong Gateway entirely. Combined with no auth plugins in Kong,
# this creates a full bypass of all security layers.

resource "aws_security_group" "analytics_sg" {
  name        = "analytics-service-sg-MISCONFIGURED"
  description = "MISCONFIGURED: Analytics service - accidentally allows public internet access"
  vpc_id      = aws_vpc.prod.id

  # BUG: Copied from ALB SG — allows inbound from 0.0.0.0/0 instead of Kong SG only
  ingress {
    description = "MISCONFIGURED: HTTP from anywhere (should be from Kong SG only)"
    from_port   = 8098
    to_port     = 8098
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "analytics-service-sg-MISCONFIGURED" }
}
