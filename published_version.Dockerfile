FROM python:3.11-slim

LABEL MAINTAINER=" Dax Mickelson dmickelson@zscaler.com"

WORKDIR /myapp

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install \
    --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org \
    -U pip zscaler-api-talkers

ENV PATH="/opt/venv/bin:$PATH"
