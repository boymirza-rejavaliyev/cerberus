FROM python:3.11-slim

WORKDIR /app

LABEL maintainer="Boymirza Rejavaliyev <boymirzarejavaliyev2003@gmail.com>"
LABEL description="CERBERUS: The 3-Headed Hybrid Security Auditor (SAST + DAST + SCA)"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENTRYPOINT ["python3", "cerberus.py"]
CMD ["--help"]
