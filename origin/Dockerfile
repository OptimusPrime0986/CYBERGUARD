FROM python:3.12-slim
RUN pip install --no-cache-dir flask==3.0.3 gunicorn==22.0.0 \
 && useradd -r -u 10001 app && mkdir /data && chown app /data
WORKDIR /srv
COPY *.py ./
USER app
EXPOSE 5000
# One worker: the demo databases live in memory. Hosts: bank.*, shop.*, anything else = original demo site.
CMD ["gunicorn", "-w", "1", "--threads", "8", "-b", "0.0.0.0:5000", "wsgi:application"]
