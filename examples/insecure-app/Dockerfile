# DELIBERATELY INSECURE test fixture for VulnSight AI.
FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
ADD . /app
USER root
CMD ["node", "/app/app.js"]
