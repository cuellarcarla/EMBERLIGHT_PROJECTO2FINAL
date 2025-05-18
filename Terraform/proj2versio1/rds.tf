# Instancia RDS PostgreSQL
resource "aws_db_instance" "app_db" {
  allocated_storage    = 20
  engine               = "postgres"
  engine_version       = "17.2-R2" # Versión con soporte extendido
  instance_class       = "db.t3.micro"
  name                 = "app-db"
  username             = "postgres"
  password             = "SecurePassword123!"
  db_subnet_group_name = aws_db_subnet_group.app_subnet_group.name
  vpc_security_group_ids = [aws_security_group.db_sg.id]

  # Desactivar copias de seguridad
  backup_retention_period = 0
  skip_final_snapshot     = true

  # Desactivar cifrado
  storage_encrypted       = false

  # Sin opciones avanzadas
  performance_insights_enabled = false
  iam_database_authentication_enabled = false

  tags = {
    Name = "app-database"
  }
}

