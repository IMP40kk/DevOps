FROM python:3.10-alpine

COPY . /bot

WORKDIR /bot

RUN apk add --no-cache postgresql-libs gcc musl-dev postgresql-dev \
    && pip install --upgrade pip \
    && pip install -r requirements.txt --no-cache-dir \
    && apk del gcc musl-dev postgresql-dev

CMD ["python", "bot.py"]

