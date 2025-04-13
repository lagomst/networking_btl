$env:TRACKERID="1123"
$env:ISLOGINREQUIRED="1"
$env:DB_NAME="test_torrent"
$env:DB_USER="root"
$env:DB_PASSWORD="admin"
$env:DB_HOST="127.0.0.1"
$env:DB_PORT="3306"
$env:SERVER_PORT="8081"


# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Go into trackers directory
cd trackers

# 5. Run Django migrations
python manage.py makemigrations download_tracker
python manage.py migrate

# 6. Run the Django server
python manage.py runserver 0.0.0.0:$env:SERVER_PORT