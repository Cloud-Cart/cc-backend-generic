FROM python:3.12

ENV PYTHONBUFFERED 1

RUN mkdir "./cloud-cart"
WORKDIR "./cloud-cart"

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 8000

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]