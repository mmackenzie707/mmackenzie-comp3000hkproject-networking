FROM nginxinc/nginx-unprivileged:1.25-alpine

#install python and pip
USER root
RUN apk add --no-cache python3 py3-pip

#virtual env
RUN python3 -m venv /venv
ENV PATH="/venv/bin:$PATH"

#pre built wheels
USER root
RUN apk add --no-cache \
    build-base \
    python3-dev \
    py3-pip \
    linux-headers \
    openblas-dev \
    lapack-dev

#copy requirments first
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

#shared sensor package
COPY smartfw /app/smartfw

#copy application code
COPY . /app
WORKDIR /app
COPY nginx.conf /etc/nginx/nginx.conf
COPY dist /usr/share/nginx/html

#start both services
CMD ["sh", "-c", "nginx & gunicorn -b 0.0.0.0:5000 app:build_app"]