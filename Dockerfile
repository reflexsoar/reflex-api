FROM python:3.8.1-slim-buster

COPY manage.py /
COPY setup.py /
COPY Pipfile /
COPY Pipfile.lock /
COPY config.py /
COPY app /app

ENV FLASK_CONFIG="production"
ENV GUNICORN_WORKERS=8
ENV GUNICORN_THREADS=2

WORKDIR /
RUN mkdir instance

RUN pip install --upgrade pip
RUN pip install pipenv
RUN pipenv install --dev
#RUN pipenv run python setup.py
#RUN pipenv run python manage.py run
CMD ["pipenv", "run", "gunicorn", "app:create_app('production')", "--preload", "-b 0.0.0.0:80", "--workers=$GUNICORN_WORKERS", "--threads=$GUNICORN_THREADS", "--worker-class=gthread"]