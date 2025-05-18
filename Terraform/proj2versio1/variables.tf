variable "region" {
  description = "La región AWS donde se desplegará la infraestructura"
  type        = string
  default     = "us-east-1"
}

variable "domain_name" {
  description = "Nombre de dominio para la aplicación"
  type        = string
  default     = "emberlight.karura.cat"
}

variable "vpc_cidr" {
  description = "CIDR block para la VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_1_cidr" {
  description = "CIDR para la primera subred pública"
  type        = string
  default     = "10.0.1.0/24"
}

variable "public_subnet_2_cidr" {
  description = "CIDR para la segunda subred pública"
  type        = string
  default     = "10.0.2.0/24"
}

variable "private_subnet_cidr" {
  description = "CIDR para la subred privada (RDS)"
  type        = string
  default     = "10.0.3.0/24"
}

variable "frontend_instance_type" {
  description = "Tipo de instancia para el servidor frontend"
  type        = string
  default     = "t2.micro"
}

variable "backend_instance_type" {
  description = "Tipo de instancia para el servidor backend"
  type        = string
  default     = "t2.small"
}

variable "key_name" {
  description = "Nombre del key pair para SSH"
  type        = string
  default     = "vockey"  # Asegúrate de tener este key pair en AWS
}

# Variables para la conexión a la base de datos RDS
variable "db_identifier" {
  description = "Identificador para la instancia RDS"
  type        = string
  default     = "appdb"
}

variable "db_name" {
  description = "Nombre de la base de datos"
  type        = string
  default     = "appdb"
}

variable "db_username" {
  description = "Usuario de la base de datos"
  type        = string
  default     = "dbadmin"
  sensitive   = true
}

variable "db_password" {
  description = "Contraseña de la base de datos"
  type        = string
  default     = "temporalpassword"  # Cambia esto en producción
  sensitive   = true
}

variable "db_instance_class" {
  description = "Clase de instancia para RDS"
  type        = string
  default     = "db.t3.micro"
}