###############################################
# Proyecto de Salud Mental - Terraform IaC
# emberlight.karura.cat
###############################################

# Configuración del proveedor AWS
provider "aws" {
  region = "us-east-1"
}

# Variables
variable "domain_name" {
  default = "emberlight.karura.cat"
  description = "Dominio principal para la aplicación"
}

variable "github_repo_frontend" {
  default = "https://github.com/cuellarcarla/emberlight_proj2.git"
  description = "Repositorio GitHub del frontend (React)"
}

variable "github_repo_backend" {
  default = "https://github.com/cuellarcarla/emberlight_backend.git"
  description = "Repositorio GitHub del backend (Django)"
}

variable "environment" {
  default = "production"
  description = "Entorno de despliegue"
}


###############################################
# NETWORKING - VPC, Subnets, SG
###############################################

# VPC Principal
resource "aws_vpc" "salud_mental_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name        = "salud-mental-vpc"
    Environment = var.environment
    Project     = "salud-mental"
  }
}

# Subnets Públicas (para ALB y EC2)
resource "aws_subnet" "public_subnet_1" {
  vpc_id                  = aws_vpc.salud_mental_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true
  
  tags = {
    Name        = "salud-mental-public-subnet-1"
    Environment = var.environment
  }
}

resource "aws_subnet" "public_subnet_2" {
  vpc_id                  = aws_vpc.salud_mental_vpc.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = true
  
  tags = {
    Name        = "salud-mental-public-subnet-2"
    Environment = var.environment
  }
}

# Subnets Privadas (para RDS)
resource "aws_subnet" "private_subnet_1" {
  vpc_id                  = aws_vpc.salud_mental_vpc.id
  cidr_block              = "10.0.3.0/24"
  availability_zone       = "us-east-1a"
  
  tags = {
    Name        = "salud-mental-private-subnet-1"
    Environment = var.environment
  }
}

resource "aws_subnet" "private_subnet_2" {
  vpc_id                  = aws_vpc.salud_mental_vpc.id
  cidr_block              = "10.0.4.0/24"
  availability_zone       = "us-east-1b"
  
  tags = {
    Name        = "salud-mental-private-subnet-2"
    Environment = var.environment
  }
}

# Internet Gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.salud_mental_vpc.id
  
  tags = {
    Name        = "salud-mental-igw"
    Environment = var.environment
  }
}

# Route Table para Subnets Públicas
resource "aws_route_table" "public_route_table" {
  vpc_id = aws_vpc.salud_mental_vpc.id
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  
  tags = {
    Name        = "salud-mental-public-rt"
    Environment = var.environment
  }
}

# Asociación de Route Table a Subnets Públicas
resource "aws_route_table_association" "public_rta_1" {
  subnet_id      = aws_subnet.public_subnet_1.id
  route_table_id = aws_route_table.public_route_table.id
}

resource "aws_route_table_association" "public_rta_2" {
  subnet_id      = aws_subnet.public_subnet_2.id
  route_table_id = aws_route_table.public_route_table.id
}

###############################################
# SECURITY GROUPS
###############################################

# SG para ALB
resource "aws_security_group" "alb_sg" {
  name        = "salud-mental-alb-sg"
  description = "Permite trafico HTTP/HTTPS al ALB"
  vpc_id      = aws_vpc.salud_mental_vpc.id
  
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
    Name        = "salud-mental-alb-sg"
    Environment = var.environment
  }
}

# SG para Backend (EC2)
resource "aws_security_group" "backend_sg" {
  name        = "salud-mental-backend-sg"
  description = "Permite trafico al backend desde ALB"
  vpc_id      = aws_vpc.salud_mental_vpc.id
  
  ingress {
    from_port       = 8000  # Puerto Django
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }
  
  ingress {
    from_port   = 22  # SSH para administración
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Recomendado restringir a IPs específicas en producción
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name        = "salud-mental-backend-sg"
    Environment = var.environment
  }
}

# SG para RDS
resource "aws_security_group" "rds_sg" {
  name        = "salud-mental-rds-sg"
  description = "Permite trafico a la base de datos desde el backend"
  vpc_id      = aws_vpc.salud_mental_vpc.id
  
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
    Name        = "salud-mental-rds-sg"
    Environment = var.environment
  }
}

###############################################
# CERTIFICADO SSL/TLS (ACM)
###############################################

# Nota: Asumiendo que el certificado se crea manualmente en AWS console
# Referencia al certificado existente por ARN o por búsqueda por dominio
data "aws_acm_certificate" "ssl_certificate" {
  domain      = var.domain_name
  statuses    = ["ISSUED"]
  most_recent = true
}

###############################################
# COGNITO - AUTENTICACIÓN
###############################################

resource "aws_cognito_user_pool" "user_pool" {
  name = "salud-mental-user-pool"
  
  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]
  
  password_policy {
    minimum_length    = 8
    require_lowercase = true
    require_numbers   = true
    require_symbols   = false
    require_uppercase = true
  }
  
  schema {
    attribute_data_type = "String"
    name                = "email"
    required            = true
    mutable             = true
  }
  
  verification_message_template {
    default_email_option = "CONFIRM_WITH_CODE"
    email_subject        = "Código de verificación para tu cuenta de Salud Mental"
    email_message        = "Tu código de verificación es {####}"
  }
  
  tags = {
    Name        = "salud-mental-user-pool"
    Environment = var.environment
  }
}

resource "aws_cognito_user_pool_client" "user_pool_client" {
  name         = "salud-mental-client"
  user_pool_id = aws_cognito_user_pool.user_pool.id
  
  generate_secret                      = false
  refresh_token_validity               = 30
  access_token_validity                = 1
  id_token_validity                    = 1
  token_validity_units {
    access_token  = "hours"
    id_token      = "hours"
    refresh_token = "days"
  }
  
  allowed_oauth_flows                  = ["implicit", "code"]
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_scopes                 = ["openid", "email", "profile"]
  
  # URLs actualizadas para usar www subdomain para el frontend
  callback_urls                        = ["https://www.${var.domain_name}/callback", "https://www.${var.domain_name}", "https://www.${var.domain_name}/login"]
  logout_urls                          = ["https://www.${var.domain_name}/logout", "https://www.${var.domain_name}"]
  supported_identity_providers         = ["COGNITO"]
  
  # Prevenir eliminación cuando se aplican cambios 
  lifecycle {
    prevent_destroy = true
  }
}

# Crear certificado ACM para el dominio personalizado
resource "aws_acm_certificate" "cognito_domain_cert" {
  domain_name       = "www.emberlight.karura.cat"
  validation_method = "DNS"

  tags = {
    Name = "emberlight-cognito-cert"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Esperar a que el certificado sea validado
resource "aws_acm_certificate_validation" "cert_validation" {
  certificate_arn = aws_acm_certificate.cognito_domain_cert.arn
}

# Configurar el dominio personalizado en Cognito
resource "aws_cognito_user_pool_domain" "main" {
  domain          = "www.emberlight.karura.cat"
  user_pool_id    = aws_cognito_user_pool.user_pool.id
  certificate_arn = aws_acm_certificate.cognito_domain_cert.arn

  depends_on = [aws_acm_certificate_validation.cert_validation]
}

resource "aws_cognito_user_pool_domain" "main" {
  domain       = "auth-${replace(var.domain_name, ".", "-")}"
  user_pool_id = aws_cognito_user_pool.user_pool.id
  
  # También podrías usar un dominio personalizado para Cognito si lo prefieres
  # Ejemplo de dominio personalizado:
  # certificate_arn = data.aws_acm_certificate.ssl_certificate.arn
  # domain          = "auth.${var.domain_name}"
}

###############################################
# RDS - BASE DE DATOS
###############################################

resource "aws_db_subnet_group" "rds_subnet_group" {
  name       = "salud-mental-db-subnet"
  subnet_ids = [aws_subnet.private_subnet_1.id, aws_subnet.private_subnet_2.id]
  
  tags = {
    Name        = "salud-mental-db-subnet"
    Environment = var.environment
  }
}

resource "aws_db_instance" "postgres" {
  identifier             = "salud-mental-db"
  allocated_storage      = 20
  engine                 = "postgres"
  engine_version         = "17.2"
  instance_class         = "db.t3.micro"
  db_name                = "saludmental"
  username               = "postgres"
  password               = "Ultrainsegura" # ¡Cambiar en producción! Considerar usar secrets_manager
  db_subnet_group_name   = aws_db_subnet_group.rds_subnet_group.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]
  multi_az               = true
  storage_encrypted      = false
  skip_final_snapshot    = true # Cambiar a false en producción
  # Sin opciones avanzadas
  performance_insights_enabled = false
  iam_database_authentication_enabled = false
  
  tags = {
    Name        = "salud-mental-postgres"
    Environment = var.environment
  }
}


###############################################
# BACKEND (EC2)
###############################################

# Script de configuración para la instancia backend
locals {
    backend_user_data = <<-EOF
        #!/bin/bash

        # Actualizar sistema
        apt update -y && apt upgrade -y

        # Instalar dependencias
        apt install -y python3 python3-pip git nginx

        # Clonar el backend
        git clone ${var.github_repo_backend} /app
        cd /app
        cd Gemini_chatbot/
        python3 -m venv venv
        source venv/bin/activate

        # Instalar dependencias de Python
        pip3 install --upgrade pip
        pip3 install gunicorn psycopg2-binary

        # Instalar dependencias del proyecto
        pip3 install -r requirements.txt

        # Crear archivo .env
        cat > /app/.env << EOL
        DATABASE_URL=postgresql://${aws_db_instance.postgres.username}:${aws_db_instance.postgres.password}@${aws_db_instance.postgres.endpoint}/${aws_db_instance.postgres.db_name}
        COGNITO_USER_POOL_ID=${aws_cognito_user_pool.user_pool.id}
        COGNITO_APP_CLIENT_ID=${aws_cognito_user_pool_client.user_pool_client.id}
        COGNITO_REGION=us-east-1
        ALLOWED_HOSTS=api.${var.domain_name},localhost
        COGNITO_DOMAIN=${aws_cognito_user_pool_domain.main.domain}.auth.us-east-1.amazoncognito.com
        FRONTEND_URL=https://www.${var.domain_name}
        DEBUG=False
        EOL

        # Migrar base de datos
        python3 manage.py migrate

        # Crear logs
        mkdir -p /app/logs
        touch /app/logs/django.log
        chmod 666 /app/logs/django.log

        # Crear servicio systemd para Gunicorn
        cat > /etc/systemd/system/gunicorn.service << EOL
        [Unit]
        Description=gunicorn daemon
        After=network.target

        [Service]
        User=root
        Group=root
        WorkingDirectory=/app
        ExecStart=/usr/local/bin/gunicorn --workers 3 --bind unix:/app/gunicorn.sock --log-file /app/logs/django.log core.wsgi:application

        [Install]
        WantedBy=multi-user.target
        EOL

        # Iniciar Gunicorn
        systemctl daemon-reload
        systemctl enable gunicorn
        systemctl start gunicorn

        # Configurar Nginx como proxy
        cat > /etc/nginx/sites-available/backend << EOL
        server {
            listen 80;
            server_name api.${var.domain_name};

            location / {
                include proxy_params;
                proxy_pass http://unix:/app/gunicorn.sock;
            }

            # Habilitar CORS para la integración con Amplify + Cognito
            location /api/ {
                include proxy_params;
                proxy_pass http://unix:/app/gunicorn.sock;
                
                # Headers CORS necesarios
                add_header 'Access-Control-Allow-Origin' 'https://www.${var.domain_name}' always;
                add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS, PUT, DELETE' always;
                add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization' always;
                add_header 'Access-Control-Allow-Credentials' 'true' always;
                
                # Manejar preflight OPTIONS
                if (\$request_method = 'OPTIONS') {
                    add_header 'Access-Control-Allow-Origin' 'https://www.${var.domain_name}' always;
                    add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS, PUT, DELETE' always;
                    add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization' always;
                    add_header 'Access-Control-Allow-Credentials' 'true' always;
                    add_header 'Access-Control-Max-Age' 1728000;
                    add_header 'Content-Type' 'text/plain charset=UTF-8';
                    add_header 'Content-Length' 0;
                    return 204;
                }
            }

            access_log /app/logs/nginx.access.log;
            error_log /app/logs/nginx.error.log;
        }
        EOL

        # Activar configuración de Nginx
        ln -s /etc/nginx/sites-available/backend /etc/nginx/sites-enabled/
        rm /etc/nginx/sites-enabled/default
        systemctl restart nginx
        EOF
}

# EC2 Backend
resource "aws_instance" "backend" {
  ami                    = "ami-084568db4383264d4"  # Cambiado a la AMI específica
  instance_type          = "t3.small"
  subnet_id              = aws_subnet.public_subnet_1.id
  vpc_security_group_ids = [aws_security_group.backend_sg.id]
  key_name               = "vockey" # Asegúrate de crear esta key-pair manualmente
  user_data              = local.backend_user_data
  
  tags = {
    Name        = "salud-mental-backend"
    Environment = var.environment
  }
}

# Crear imagen AMI desde la instancia EC2
resource "aws_ami_from_instance" "backend_ami" {
  name               = "salud-mental-backend-ami"
  source_instance_id = aws_instance.backend.id
  
  tags = {
    Name        = "salud-mental-backend-ami"
    Environment = var.environment
  }
  
  # Esperar a que la instancia se inicialice completamente
  depends_on = [aws_instance.backend]
}

###############################################
# AUTO SCALING GROUP Y LOAD BALANCER
###############################################

# Launch Configuration para Auto Scaling
resource "aws_launch_configuration" "backend_lc" {
  name_prefix          = "salud-mental-backend-lc-"
  image_id             = aws_ami_from_instance.backend_ami.id
  instance_type        = "t3.small"
  security_groups      = [aws_security_group.backend_sg.id]
  key_name             = "vockey"  # Usar la misma clave que la instancia inicial
  
  lifecycle {
    create_before_destroy = true
  }
}

# Auto Scaling Group
resource "aws_autoscaling_group" "backend_asg" {
  name                 = "salud-mental-backend-asg"
  launch_configuration = aws_launch_configuration.backend_lc.name
  vpc_zone_identifier  = [aws_subnet.public_subnet_1.id, aws_subnet.public_subnet_2.id]
  min_size             = 1
  max_size             = 3
  desired_capacity     = 2
  
  health_check_type         = "ELB"
  health_check_grace_period = 300
  
  tag {
    key                 = "Name"
    value               = "salud-mental-backend-asg"
    propagate_at_launch = true
  }
  
  tag {
    key                 = "Environment"
    value               = var.environment
    propagate_at_launch = true
  }
  
  # Esperar a que la AMI esté disponible
  depends_on = [aws_ami_from_instance.backend_ami]
}

# Política de Auto Scaling por CPU
resource "aws_autoscaling_policy" "backend_cpu_policy" {
  name                   = "backend-cpu-policy"
  autoscaling_group_name = aws_autoscaling_group.backend_asg.name
  policy_type            = "TargetTrackingScaling"
  
  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = 70.0
  }
}

# Application Load Balancer
resource "aws_lb" "backend_alb" {
  name               = "salud-mental-backend-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = [aws_subnet.public_subnet_1.id, aws_subnet.public_subnet_2.id]
  
  tags = {
    Name        = "salud-mental-backend-alb"
    Environment = var.environment
  }
}

# Target Group para el ALB
resource "aws_lb_target_group" "backend_tg" {
  name     = "salud-mental-backend-tg"
  port     = 8000
  protocol = "HTTP"
  vpc_id   = aws_vpc.salud_mental_vpc.id
  
  health_check {
    path                = "/api/health/"
    port                = "traffic-port"
    healthy_threshold   = 3
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    matcher             = "200"
  }
  
  tags = {
    Name        = "salud-mental-backend-tg"
    Environment = var.environment
  }
}

# Listener HTTPS para el ALB
resource "aws_lb_listener" "backend_https" {
  load_balancer_arn = aws_lb.backend_alb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = data.aws_acm_certificate.ssl_certificate.arn
  
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.backend_tg.arn
  }
}

# Listener HTTP para redirección a HTTPS
resource "aws_lb_listener" "backend_http_redirect" {
  load_balancer_arn = aws_lb.backend_alb.arn
  port              = 80
  protocol          = "HTTP"
  
  default_action {
    type = "redirect"
    
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# Adjuntar Auto Scaling Group al Target Group
resource "aws_autoscaling_attachment" "backend_asg_attachment" {
  autoscaling_group_name = aws_autoscaling_group.backend_asg.name
  lb_target_group_arn    = aws_lb_target_group.backend_tg.arn
}

###############################################
# ROUTE 53 - DNS
###############################################

# Buscar la zona hospedada existente
data "aws_route53_zone" "hosted_zone" {
  name = var.domain_name
}

# Registro Route 53 para Backend API
resource "aws_route53_record" "backend_api" {
  zone_id = data.aws_route53_zone.hosted_zone.zone_id
  name    = "api.${var.domain_name}"
  type    = "A"
  
  alias {
    name                   = aws_lb.backend_alb.dns_name
    zone_id                = aws_lb.backend_alb.zone_id
    evaluate_target_health = true
  }
}

###############################################
# CLOUDWATCH - MONITOREO BÁSICO
###############################################

# Dashboard simple de CloudWatch
resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "salud-mental-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/EC2", "CPUUtilization", "AutoScalingGroupName", aws_autoscaling_group.backend_asg.name]
          ]
          period = 300
          stat   = "Average"
          region = "us-east-1"
          title  = "Backend CPU"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", aws_db_instance.postgres.id]
          ]
          period = 300
          stat   = "Average"
          region = "us-east-1"
          title  = "RDS CPU"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", aws_lb.backend_alb.arn_suffix]
          ]
          period = 300
          stat   = "Sum"
          region = "us-east-1"
          title  = "ALB Request Count"
        }
      }
    ]
  })
}

###############################################
# OUTPUTS
###############################################

output "cognito_user_pool_id" {
  value = aws_cognito_user_pool.user_pool.id
  description = "ID del pool de usuarios de Cognito"
}

output "cognito_app_client_id" {
  value = aws_cognito_user_pool_client.user_pool_client.id
  description = "ID del cliente de app de Cognito"
}

output "cognito_domain" {
  value = "${aws_cognito_user_pool_domain.main.domain}.auth.us-east-1.amazoncognito.com"
  description = "Dominio de Cognito para autenticación"
}

output "frontend_url" {
  value = "https://www.${var.domain_name}"
  description = "URL del frontend"
}

output "backend_api_url" {
  value = "https://api.${var.domain_name}"
  description = "URL de la API backend"
}

output "backend_instance_id" {
  value = aws_instance.backend.id
  description = "ID de la instancia EC2 del backend"
}

output "rds_endpoint" {
  value = aws_db_instance.postgres.endpoint
  description = "Endpoint de la base de datos RDS"
}