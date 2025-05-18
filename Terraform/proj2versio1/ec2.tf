# EC2 para Frontend (React)
resource "aws_instance" "frontend_ec2" {
  ami                    = "ami-084568db4383264d4" # Usar la AMI específica
  instance_type          = var.frontend_instance_type
  key_name               = var.key_name
  subnet_id              = aws_subnet.public_subnet_1.id
  vpc_security_group_ids = [aws_security_group.frontend_sg.id]
  iam_instance_profile   = "LabRole"  # Usando el rol existente

  user_data = <<-EOF
    #!/bin/bash
    # Actualizar paquetes
    apt-get update
    apt-get upgrade -y
    
    # Instalar Node.js y npm
    apt-get install -y curl
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    apt-get install -y nodejs
    
    # Instalar Nginx
    apt-get install -y nginx

    # Configurar Nginx para React
    cat > /etc/nginx/sites-available/default << 'EOL'
    server {
        listen 80 default_server;
        listen [::]:80 default_server;

        root /var/www/html/build;
        index index.html index.htm;

        server_name _;

        location / {
            try_files $uri $uri/ /index.html;
        }
    }
    EOL
    
    # Instalar Git
    apt-get install -y git
    
    # Crear directorio para la aplicación
    mkdir -p /var/www/html
    
    # Aquí deberás clonar tu repositorio de frontend
    # git clone https://tu-repositorio/frontend.git /var/www/html
    
    # Como ejemplo, creamos una aplicación React simple
    cd /var/www/html
    npx create-react-app .
    
    # Configuración del archivo .env para conectar con el backend
    cat > .env << 'EOL'
    REACT_APP_API_URL=http://${aws_instance.backend_ec2.private_ip}:8000/api
    EOL
    
    # Construir la aplicación React
    npm run build
    
    # Reiniciar Nginx
    systemctl restart nginx
    
    echo "Instalación del frontend completada" > /var/log/frontend-complete.log
  EOF

  tags = {
    Name = "frontend-server"
  }

  depends_on = [
    aws_internet_gateway.app_igw
  ]
}

# EC2 para Backend (Django)
resource "aws_instance" "backend_ec2" {
  ami                    = "ami-084568db4383264d4" # Usar la AMI específica
  instance_type          = var.backend_instance_type
  key_name               = var.key_name
  subnet_id              = aws_subnet.public_subnet_1.id
  vpc_security_group_ids = [aws_security_group.backend_sg.id]
  iam_instance_profile   = "LabRole"  # Usando el rol existente

  user_data = <<-EOF
    #!/bin/bash
    # Actualizar paquetes
    apt-get update
    apt-get upgrade -y
    
    # Instalar Python y dependencias
    apt-get install -y python3 python3-pip python3-venv postgresql postgresql-contrib libpq-dev
    
    # Instalar Nginx
    apt-get install -y nginx

    # Configurar Nginx para proxy inverso a Django
    cat > /etc/nginx/sites-available/default << 'EOL'
    server {
        listen 80 default_server;
        listen [::]:80 default_server;

        server_name _;

        location /static/ {
            alias /opt/app/static/;
        }

        location /media/ {
            alias /opt/app/media/;
        }

        location / {
            proxy_pass http://127.0.0.1:8000;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }
    }
    EOL
    
    # Instalar Git
    apt-get install -y git
    
    # Crear directorio para la aplicación
    mkdir -p /opt/app
    
    # Aquí deberás clonar tu repositorio de backend
    # git clone https://tu-repositorio/backend.git /opt/app
    
    # Como ejemplo, creamos un entorno virtual y proyecto Django simple
    cd /opt/app
    python3 -m venv venv
    source venv/bin/activate
    pip install django psycopg2-binary gunicorn
    
    # Crear un proyecto Django de ejemplo
    django-admin startproject config .
    
    # Configuración para conectar a la base de datos RDS
    cat > config/settings.py << 'EOL'
    import os
    from pathlib import Path

    BASE_DIR = Path(__file__).resolve().parent.parent
    SECRET_KEY = 'django-insecure-abc123'  # Cambia esto en producción
    DEBUG = False
    ALLOWED_HOSTS = ['*']  # Restringe esto en producción

    INSTALLED_APPS = [
        'django.contrib.admin',
        'django.contrib.auth',
        'django.contrib.contenttypes',
        'django.contrib.sessions',
        'django.contrib.messages',
        'django.contrib.staticfiles',
        'corsheaders',
        'rest_framework',
    ]

    MIDDLEWARE = [
        'django.middleware.security.SecurityMiddleware',
        'django.contrib.sessions.middleware.SessionMiddleware',
        'corsheaders.middleware.CorsMiddleware',
        'django.middleware.common.CommonMiddleware',
        'django.middleware.csrf.CsrfViewMiddleware',
        'django.contrib.auth.middleware.AuthenticationMiddleware',
        'django.contrib.messages.middleware.MessageMiddleware',
        'django.middleware.clickjacking.XFrameOptionsMiddleware',
    ]

    ROOT_URLCONF = 'config.urls'

    TEMPLATES = [
        {
            'BACKEND': 'django.template.backends.django.DjangoTemplates',
            'DIRS': [],
            'APP_DIRS': True,
            'OPTIONS': {
                'context_processors': [
                    'django.template.context_processors.debug',
                    'django.template.context_processors.request',
                    'django.contrib.auth.context_processors.auth',
                    'django.contrib.messages.context_processors.messages',
                ],
            },
        },
    ]

    WSGI_APPLICATION = 'config.wsgi.application'

    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': '${var.db_name}',
            'USER': '${var.db_username}',
            'PASSWORD': '${var.db_password}',
            'HOST': '${aws_db_instance.app_db.endpoint}',
            'PORT': '5432',
        }
    }

    AUTH_PASSWORD_VALIDATORS = [
        {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
        {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
        {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
        {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
    ]

    LANGUAGE_CODE = 'en-us'
    TIME_ZONE = 'UTC'
    USE_I18N = True
    USE_TZ = True

    STATIC_URL = '/static/'
    STATIC_ROOT = os.path.join(BASE_DIR, 'static')
    MEDIA_URL = '/media/'
    MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

    DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

    CORS_ALLOW_ALL_ORIGINS = True  # Restringe esto en producción
    EOL
    
    # Instalar dependencias adicionales
    pip install django-cors-headers djangorestframework
    
    # Crear directorios para static y media
    mkdir -p static media
    
    # Aplicar migraciones
    python manage.py migrate
    
    # Recopilar archivos estáticos
    python manage.py collectstatic --noinput
    
    # Crear archivo de servicio systemd para Gunicorn
    cat > /etc/systemd/system/gunicorn.service << 'EOL'
    [Unit]
    Description=gunicorn daemon
    After=network.target

    [Service]
    User=root
    Group=www-data
    WorkingDirectory=/opt/app
    ExecStart=/opt/app/venv/bin/gunicorn --access-logfile - --workers 3 --bind 0.0.0.0:8000 config.wsgi:application

    [Install]
    WantedBy=multi-user.target
    EOL
    
    # Habilitar y iniciar el servicio de Gunicorn
    systemctl enable gunicorn
    systemctl start gunicorn
    
    # Reiniciar Nginx
    systemctl restart nginx
    
    echo "Instalación del backend completada" > /var/log/backend-complete.log
  EOF

  tags = {
    Name = "backend-server"
  }

  depends_on = [
    aws_internet_gateway.app_igw,
    aws_db_instance.app_db
  ]
}