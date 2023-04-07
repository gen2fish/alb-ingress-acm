FROM python:3.11

WORKDIR /code

COPY ./requirements.txt /code/requirements.txt

RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

COPY ./acm-route53-operator.py /code/acm-route53-operator.py

CMD ["kopf", "run", "acm-route53-operator.py"]
