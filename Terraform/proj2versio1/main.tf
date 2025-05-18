provider "aws" {
  region = var.region
}

# VPC
resource "aws_vpc" "app_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  
  tags = {
    Name = "app-vpc"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "app_igw" {
  vpc_id = aws_vpc.app_vpc.id
  
  tags = {
    Name = "app-igw"
  }
}

# Subredes públicas
resource "aws_subnet" "public_subnet_1" {
  vpc_id                  = aws_vpc.app_vpc.id
  cidr_block              = var.public_subnet_1_cidr
  map_public_ip_on_launch = true
  availability_zone       = "${var.region}a"
  
  tags = {
    Name = "app-public-subnet-1"
  }
}

resource "aws_subnet" "public_subnet_2" {
  vpc_id                  = aws_vpc.app_vpc.id
  cidr_block              = var.public_subnet_2_cidr
  map_public_ip_on_launch = true
  availability_zone       = "${var.region}b"
  
  tags = {
    Name = "app-public-subnet-2"
  }
}

# Subred privada para RDS
resource "aws_subnet" "private_subnet" {
  vpc_id            = aws_vpc.app_vpc.id
  cidr_block        = var.private_subnet_cidr
  availability_zone = "${var.region}a"
  
  tags = {
    Name = "app-private-subnet"
  }
}

# Para cumplir con el requisito de RDS que necesita al menos 2 subredes en diferentes AZs
resource "aws_subnet" "private_subnet_2" {
  vpc_id            = aws_vpc.app_vpc.id
  cidr_block        = "10.0.4.0/24"  # Diferente CIDR que private_subnet
  availability_zone = "${var.region}b"
  
  tags = {
    Name = "app-private-subnet-2"
  }
}

# Tabla de rutas pública
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.app_vpc.id
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.app_igw.id
  }
  
  tags = {
    Name = "app-public-rt"
  }
}

# Asociaciones de subredes públicas con tabla de rutas
resource "aws_route_table_association" "public_rta_1" {
  subnet_id      = aws_subnet.public_subnet_1.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "public_rta_2" {
  subnet_id      = aws_subnet.public_subnet_2.id
  route_table_id = aws_route_table.public_rt.id
}

# Grupo de seguridad para ALB
resource "aws_security_group" "alb_sg" {
  name        = "app-alb-sg"
  description = "Security group for Application Load Balancer"
  vpc_id      = aws_vpc.app_vpc.id
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "app-alb-sg"
  }
}

# Grupo de seguridad para Frontend
resource "aws_security_group" "frontend_sg" {
  name        = "app-frontend-sg"
  description = "Security group for Frontend EC2"
  vpc_id      = aws_vpc.app_vpc.id
  
  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    cidr_blocks     = ["0.0.0.0/0"]  # Restringe esto en producción
  }
  
  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }
  
  ingress {
    from_port       = 3000  # Puerto para React
    to_port         = 3000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "app-frontend-sg"
  }
}

# Grupo de seguridad para Backend
resource "aws_security_group" "backend_sg" {
  name        = "app-backend-sg"
  description = "Security group for Backend EC2"
  vpc_id      = aws_vpc.app_vpc.id
  
  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    cidr_blocks     = ["0.0.0.0/0"]  # Restringe esto en producción
  }
  
  ingress {
    from_port       = 8000  # Puerto para Django
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id, aws_security_group.frontend_sg.id]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "app-backend-sg"
  }
}

# Grupo de seguridad para RDS
resource "aws_security_group" "rds_sg" {
  name        = "app-rds-sg"
  description = "Security group for RDS"
  vpc_id      = aws_vpc.app_vpc.id
  
  ingress {
    from_port       = 5432  # Puerto PostgreSQL
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.backend_sg.id]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "app-rds-sg"
  }
}

# Grupo de subredes para RDS
resource "aws_db_subnet_group" "rds_subnet_group" {
  name       = "app-rds-subnet-group"
  subnet_ids = [aws_subnet.private_subnet.id, aws_subnet.private_subnet_2.id]
  
  tags = {
    Name = "app-rds-subnet-group"
  }
}