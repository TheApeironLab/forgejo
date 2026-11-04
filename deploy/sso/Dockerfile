ARG FORGEJO_IMAGE=codeberg.org/forgejo/forgejo:15.0.9@sha256:91a5310c86934339e16bd06b6078aada836e3d8935b2d70f6598108cbfaed5d1
FROM ${FORGEJO_IMAGE}
USER root
RUN apk add --no-cache python3 postgresql-client
COPY sync.py /opt/code-sso/sync.py
USER 1000:1000
ENTRYPOINT ["python3", "/opt/code-sso/sync.py"]
