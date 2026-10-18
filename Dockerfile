FROM python:3.12-slim
RUN useradd --system --uid 10001 --no-create-home relay
WORKDIR /app
COPY app.py ./
COPY vendor ./vendor
COPY static ./static
USER relay
ENV WEB_BIND=0.0.0.0 PYTHONUNBUFFERED=1
EXPOSE 11544/udp 8080/tcp
CMD ["python", "-u", "app.py"]
