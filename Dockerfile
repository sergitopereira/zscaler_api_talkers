FROM python:3.8
WORKDIR /
RUN git clone https://bitbucket.corp.zscaler.com/scm/zat/zscaler_api_talkers.git /zscaler_api_talkers
RUN pip install -r /zscaler_api_talkers/requirements.txt --trusted-host pypi.org --trusted-host files.pythonhosted.org