# Lineage container image.
#
# Stage 1: pull the `oc` binary from the official origin-cli image.
# Stage 2: small Python base + Lineage + requirements + oc.
#
# Runtime: `python run.py` listens on 0.0.0.0:8080.
# Inside an OpenShift pod, oc automatically uses the pod ServiceAccount
# token — no kubeconfig generation needed.

FROM quay.io/openshift/origin-cli:4.19 AS oc

FROM python:3.11-slim-bookworm

COPY --from=oc /usr/bin/oc /usr/local/bin/oc

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY run.py ./
COPY lineage ./lineage

ENV LINEAGE_HOST=0.0.0.0 \
    LINEAGE_PORT=8080 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/tmp

EXPOSE 8080

USER 1001

CMD ["python", "run.py"]
