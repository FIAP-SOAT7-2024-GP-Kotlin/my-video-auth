FROM postgres:16

COPY schema.sql /docker-entrypoint-initdb.d/1-schema.sql
RUN chmod +x /docker-entrypoint-initdb.d/1-schema.sql

EXPOSE 5432
