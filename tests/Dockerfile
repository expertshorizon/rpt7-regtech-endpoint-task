FROM public.ecr.aws/docker/library/python:3.13-slim-bookworm@sha256:01f42367a0a94ad4bc17111776fd66e3500c1d87c15bbd6055b7371d39c124fb

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.lock /tmp/requirements.lock
RUN pip install --no-cache-dir --require-hashes --no-deps -r /tmp/requirements.lock

RUN mkdir -p /app/data /app/src

RUN groupadd -g 65532 rpt7runner \
    && useradd -u 65532 -g rpt7runner -M -s /usr/sbin/nologin rpt7runner

COPY test.sh test_outputs.py conftest.py schema_data.py held_out_data.py /tests/
COPY fixtures/ /tests/fixtures/
RUN chmod +x /tests/test.sh

CMD ["/tests/test.sh"]
