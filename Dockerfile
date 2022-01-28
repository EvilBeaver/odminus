FROM evilbeaver/onescript:1.6.0

COPY src /app
WORKDIR /app
RUN opm install -l

FROM evilbeaver/oscript-web:0.9.0
COPY --from=a4neg/1c-centos7-docker /opt/1C/v8.3/x86_64 /opt/1C/v8.3/x86_64

ENV ASPNETCORE_ENVIRONMENT=Production
COPY --from=0 /app .
