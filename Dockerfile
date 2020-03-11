FROM python:3.7-alpine
COPY requirements.txt /
COPY . /catscan
RUN apk add --update --no-cache g++ gcc libxslt-dev
RUN apk add --no-cache gcc musl-dev linux-headers
RUN pip3 install -r /requirements.txt
WORKDIR /catscan 
CMD ["python", "./catscan.py"]
