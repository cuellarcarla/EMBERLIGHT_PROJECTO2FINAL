#!/bin/bash

# 1. Actualizar el sistema y herramientas
sudo apt update -y
sudo apt upgrade -y
sudo apt install git python3 python3-pip python3-venv nginx -y

# 2. Clonar el repositorio
echo "Clonando el repositorio..."
git clone https://github.com/getaudio2/EmberLight_Projecte2.git 
cd EmberLight_Projecte2

# 3. Construir el frontend (React)
echo "Construyendo el frontend..."
cd frontend
npm install
npm run build

# 4. Crear un entorno virtual y activarlo
echo "Creando entorno virtual..."
cd ..
python3 -m venv venv
source venv/bin/activate

# 5. Instalar dependencias de Python
echo "Instalando dependencias..."
pip install --upgrade pip
pip install django djangorestframework google-generativeai django-cors-headers psycopg2-binary python-dotenv

# 6. Configurar variables de entorno
echo "Configurando archivo .env..."
cat <<EOL > Gemini_chatbot/EmberLight/.env
DJANGO_SECRET_KEY=django-insecure-kgy59+zduis9$5ym7h7+156a3v%dwlkxk@kimronnw-x6ojb)0
GEMINI_API_KEY=AIzaSyAymZPUP99PmsOJ3yR6bL9ZIiK28mOp9W8

DB_HOST=emberlight-db.cspfe1inrs2v.us-east-1.rds.amazonaws.com
DB_NAME=appdb
DB_USER=postgres
DB_PASSWORD=ultrainsegura
DB_PORT=5432
EOL

# 7. Configurar STATIC_ROOT en settings.py
echo "Configurando STATIC_ROOT en settings.py..."

# Agregar STATIC_ROOT manualmente
if ! grep -q "STATIC_ROOT" Gemini_chatbot/EmberLight/settings.py; then
    echo "STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')" >> Gemini_chatbot/EmberLight/settings.py
fi

# 8. Migrar la base de datos a RDS
echo "Migrando la base de datos..."
cd Gemini_chatbot/EmberLight
python manage.py makemigrations
python manage.py migrate

# 9. Recopilar archivos estáticos
echo "Recopilando archivos estáticos..."
python manage.py collectstatic --noinput

# 10. Configurar Gunicorn para servir el backend
echo "Configurando Gunicorn..."
pip install gunicorn
sudo tee /etc/systemd/system/gunicorn.service <<EOL
[Unit]
Description=gunicorn daemon for Django app
After=network.target

[Service]
User=ubuntu
Group=www-data
WorkingDirectory=/home/ubuntu/EmberLight_Projecte2/Gemini_chatbot/EmberLight
ExecStart=/home/ubuntu/EmberLight_Projecte2/venv/bin/gunicorn --workers 3 --bind unix:/home/ubuntu/EmberLight_Projecte2/Gemini_chatbot/EmberLight.sock EmberLight.wsgi:application

[Install]
WantedBy=multi-user.target
EOL

sudo systemctl start gunicorn
sudo systemctl enable gunicorn

# 11. Configurar Nginx para servir el frontend y proxy al backend
echo "Configurando Nginx..."
sudo tee /etc/nginx/sites-available/emberlight <<EOL
server {
    listen 80;
    server_name emberlight.karura.cat;

    location / {
        root /home/ubuntu/EmberLight_Projecte2/frontend/build;
        index index.html;
        try_files \$uri /index.html;
    }

    location /api/ {
        proxy_pass http://unix:/home/ubuntu/EmberLight_Projecte2/Gemini_chatbot/EmberLight.sock;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOL

sudo ln -s /etc/nginx/sites-available/emberlight /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx

# 12. Limpiar y finalizar
echo "Despliegue completado. Accede a tu aplicación en https://emberlight.karura.cat/ "