FROM evilbeaver/oscript-web:dev

COPY --from=a4neg/1c-centos7-docker /opt/1C/v8.3/x86_64 /opt/1C/v8.3/x86_64

COPY src/ /app
