FROM python:latest

WORKDIR /app

RUN pip install requests

RUN pip install requests-toolbelt

COPY . .

CMD ./wait-for-it.sh mobsf:8000 -- python scan.py
