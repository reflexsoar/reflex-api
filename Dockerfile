FROM python:3.8.1-slim-buster

COPY manage.py /
COPY setup.py /
COPY Pipfile /
COPY Pipfile.lock /
COPY config.py /
COPY app /app

ENV FLASK_CONFIG="production"

WORKDIR /
RUN mkdir instance

RUN pip install --upgrade pip
RUN pip install pipenv
RUN pipenv install --dev
#RUN pipenv run python setup.py
#RUN pipenv run python manage.py run