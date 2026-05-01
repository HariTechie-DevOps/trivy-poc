# ============================================================
# Intentionally MISCONFIGURED Dockerfile
# Trivy misconfig scanner will catch all these issues
# ============================================================

# MISCONFIG 1: Using very old base image with many CVEs
FROM python:3.6-slim

# MISCONFIG 2: Running as ROOT user (never do this in prod)
# Should use: RUN useradd -m appuser && USER appuser
USER root

# MISCONFIG 3: Hardcoded secrets in ENV
ENV SECRET_KEY="hardcoded-secret-in-dockerfile"
ENV DB_PASSWORD="admin123"
ENV AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Set working directory
WORKDIR /app

# MISCONFIG 4: Copying everything including .env, .git, secrets
# Should use .dockerignore
COPY . .

# MISCONFIG 5: Not pinning pip version, running as root
RUN pip install -r requirements.txt

# MISCONFIG 6: Exposing unnecessary ports
EXPOSE 5000
EXPOSE 22
EXPOSE 3306
EXPOSE 6379

# MISCONFIG 7: No HEALTHCHECK defined
# Should have: HEALTHCHECK CMD curl -f http://localhost:5000/ || exit 1

# MISCONFIG 8: Using shell form instead of exec form (PID 1 issue)
# Should be: CMD ["python", "app.py"]
CMD python app.py
