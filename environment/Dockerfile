FROM public.ecr.aws/docker/library/gcc:13-bookworm@sha256:930f2ebe239275fa67226654cb79273ea34eee672ae61c8a39f689c37fb7ac5c

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        asciinema \
        ca-certificates \
        curl \
        libsqlite3-dev \
        sqlite3 \
        tmux \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /app/data /app/src

COPY app/data/schema.sql /app/data/schema.sql
RUN sqlite3 /app/data/rpt7.db < /app/data/schema.sql

COPY app/src/ /app/src/

CMD ["sleep", "infinity"]
