# VulnLens VPC — private subnet for Fargate, public subnet for NAT Gateway
# Fargate tasks process uploaded source code and should not be internet-facing.
# VPC Endpoints for S3 and DynamoDB keep traffic within AWS's private network.

# ── VPC ──────────────────────────────────────────────────────────────────────

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Project = var.project
    Name    = "${var.project}-vpc"
  }
}

# ── SUBNETS ───────────────────────────────────────────────────────────────────

# Public subnet — NAT Gateway lives here
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Project = var.project
    Name    = "${var.project}-public"
  }
}

# Private subnet — Fargate tasks run here, no direct internet access
resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "${var.aws_region}a"

  tags = {
    Project = var.project
    Name    = "${var.project}-private"
  }
}

# ── INTERNET GATEWAY ──────────────────────────────────────────────────────────

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Project = var.project
    Name    = "${var.project}-igw"
  }
}

# ── NAT GATEWAY ───────────────────────────────────────────────────────────────
# Allows Fargate tasks in the private subnet to make outbound internet calls
# (e.g. pulling npm packages) without being directly reachable from the internet.

resource "aws_eip" "nat" {
  domain = "vpc"

  tags = {
    Project = var.project
    Name    = "${var.project}-nat-eip"
  }
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public.id

  tags = {
    Project = var.project
    Name    = "${var.project}-nat"
  }

  depends_on = [aws_internet_gateway.main]
}

# ── ROUTE TABLES ─────────────────────────────────────────────────────────────

# Public route table — routes internet traffic through IGW
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Project = var.project
    Name    = "${var.project}-rt-public"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Private route table — routes internet traffic through NAT Gateway
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }

  tags = {
    Project = var.project
    Name    = "${var.project}-rt-private"
  }
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

# ── SECURITY GROUPS ───────────────────────────────────────────────────────────

# Security group for Fargate tasks — only allows outbound traffic
# No inbound from internet; scanner is triggered internally, not via public URL
resource "aws_security_group" "fargate" {
  name        = "${var.project}-fargate-sg"
  description = "Security group for VulnLens Fargate tasks"
  vpc_id      = aws_vpc.main.id

  # Allow all outbound (needed for ECR pull, S3, DynamoDB via VPC endpoints)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = {
    Project = var.project
    Name    = "${var.project}-fargate-sg"
  }
}

# ── VPC ENDPOINTS ─────────────────────────────────────────────────────────────
# S3 and DynamoDB traffic stays within AWS — never touches the public internet.
# Gateway endpoints are free; no per-hour charge unlike Interface endpoints.

# S3 Gateway Endpoint
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = {
    Project = var.project
    Name    = "${var.project}-vpce-s3"
  }
}

# DynamoDB Gateway Endpoint
resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = {
    Project = var.project
    Name    = "${var.project}-vpce-dynamodb"
  }
}
