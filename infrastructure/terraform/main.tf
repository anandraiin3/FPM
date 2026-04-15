# ============================================================================
# Terraform — VPC, Security Groups, NACLs, WAF
# Realistic production-like security posture for FPM knowledge base.
# ============================================================================

# ---------- VPC ----------

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "prod-vpc"
  }
}

resource "aws_subnet" "public_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"
  tags = { Name = "public-subnet-a" }
}

resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.10.0/24"
  availability_zone = "us-east-1a"
  tags = { Name = "private-subnet-a" }
}

resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.11.0/24"
  availability_zone = "us-east-1b"
  tags = { Name = "private-subnet-b" }
}

# ---------- ALB Security Group ----------
# Public-facing Application Load Balancer — allows inbound 443/80 from 0.0.0.0/0 only.

resource "aws_security_group" "alb_sg" {
  name        = "alb-public-sg"
  description = "Public ALB - allows inbound HTTPS/HTTP from anywhere"
  vpc_id      = aws_vpc.main.id

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
  vpc_id      = aws_vpc.main.id

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
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Service traffic from Kong Gateway"
    from_port       = 8080
    to_port         = 8090
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

# ---------- Fetch Service Security Group ----------
# Allows egress to partner CIDR only — blocks internal CIDR to prevent SSRF pivot.

resource "aws_security_group" "fetch_service_sg" {
  name        = "fetch-service-sg"
  description = "Fetch service - egress restricted to partner CIDR only, blocks internal"
  vpc_id      = aws_vpc.main.id

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

  # Explicit deny for internal CIDR (VPC range) and metadata endpoint
  # Note: AWS SGs are allow-only, so the restricted egress above implicitly
  # blocks 10.0.0.0/16 and 169.254.169.254/32 since they are not listed.

  tags = { Name = "fetch-service-sg" }
}

# ---------- NACLs for internal-only endpoints ----------

resource "aws_network_acl" "internal_nacl" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]

  # Allow inbound from VPC only
  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "10.0.0.0/16"
    from_port  = 8080
    to_port    = 8090
  }

  # Deny inbound from internet
  ingress {
    protocol   = "tcp"
    rule_no    = 200
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

  tags = { Name = "internal-endpoints-nacl" }
}

# ---------- WAF Web ACL ----------
# Associates AWS Managed Rule Groups for SQLi and Common Rule Set.

resource "aws_wafv2_web_acl" "api_waf" {
  name        = "api-waf-acl"
  description = "WAF ACL for API Gateway — blocks common attacks"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  # AWS Managed Rule: Common Rule Set
  rule {
    name     = "aws-common-rules"
    priority = 1

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

  # AWS Managed Rule: SQL Injection
  rule {
    name     = "aws-sqli-rules"
    priority = 2

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

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "api-waf-acl"
    sampled_requests_enabled   = true
  }

  tags = { Name = "api-waf-acl" }
}

# Associate WAF with ALB
resource "aws_wafv2_web_acl_association" "alb_waf" {
  resource_arn = aws_lb.api_alb.arn
  web_acl_arn  = aws_wafv2_web_acl.api_waf.arn
}

resource "aws_lb" "api_alb" {
  name               = "api-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = [aws_subnet.public_a.id]

  tags = { Name = "api-alb" }
}
