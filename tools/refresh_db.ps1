rm  *.db
rm -force ./migrations/
python manage.py db init
python manage.py db migrate
python manage.py db upgrade
python manage.py setup
python manage.py run
