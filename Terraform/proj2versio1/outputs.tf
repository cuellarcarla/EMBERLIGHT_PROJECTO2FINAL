output "vpc_id" {
  description = "ID de la VPC"
  value       = aws_vpc.app_vpc.id
}

output "frontend_instance_public_ip" {
  description = "IP pública de la instancia frontend"
  value       = aws_instance.frontend_ec2.public_ip
}

output "backend_instance_public_ip" {
  description = "IP pública de la instancia backend"
  value       = aws_instance.backend_ec2.public_ip
}

output "frontend_instance_private_ip" {
  description = "IP privada de la instancia frontend"
  value       = aws_instance.frontend_ec2.private_ip
}

output "backend_instance_private_ip" {
  description = "IP privada de la instancia backend"
  value       = aws_instance.backend_ec2.private_ip
}

output "rds_endpoint" {
  description = "Endpoint de la base de datos RDS"
  value       = aws_db_instance.app_db.endpoint
}

output "alb_dns_name" {
  description = "DNS del ALB"
  value       = aws_lb.app_alb.dns_name
}

output "domain_name" {
  description = "Nombre de dominio de la aplicación"
  value       = var.domain_name
}

output "nameservers" {
  description = "Nameservers para configurar en el registrador de dominio"
  value       = aws_route53_zone.app_zone.name_servers
}