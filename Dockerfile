FROM python:3.8.1-slim-buster

COPY setup.py /
COPY Pipfile /
COPY Pipfile.lock /
COPY config.py /
COPY app /app

ENV GUNICORN_WORKERS=8
ENV GUNICORN_THREADS=2
ENV REFLEX_API_PORT=80

WORKDIR /
RUN apt-get update \
&& apt-get install -y --no-install-recommends git \
&& mkdir instance \
&& pip install --upgrade pip \
&& pip install pipenv \
&& pipenv install \
&& pipenv install tzdata

CMD ["pipenv", "run", "gunicorn", "app:create_app('production')", "--preload", "-b 0.0.0.0:$REFLEX_API_PORT", "--workers=$GUNICORN_WORKERS", "--threads=$GUNICORN_THREADS", "--worker-class=gthread"]
