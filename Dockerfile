FROM python:3.12-slim
RUN useradd --system --uid 10001 --no-create-home relay && mkdir /data && chown relay /data
WORKDIR /app
COPY app.py ./
COPY rooms.py ./
COPY vendor ./vendor
COPY static ./static
USER relay
ENV WEB_BIND=0.0.0.0 PYTHONUNBUFFERED=1 GAME_NAMES_FILE=/data/game_names.json
EXPOSE 11544/udp 8080/tcp
CMD ["python", "-u", "app.py"]
