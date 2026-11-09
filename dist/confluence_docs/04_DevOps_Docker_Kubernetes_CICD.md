# AI-Based Network Intrusion Detection System
## Software Engineering Capstone — Confluence Documentation Pack: Volume 4
### DevOps, Docker Containerization, Kubernetes Orchestration & CI/CD Runbook

---

### 1. Multi-Stage Docker Containerization
The system is packaged into a secure, hardened Docker container using `python:3.11-slim`:
* **Non-root execution:** Runs as `appuser` (UID 1000) for security hardening.
* **Minimal attack surface:** Image size < 200MB.
* **Healthcheck:** Queries Streamlit core endpoint `/_stcore/health`.
* **Port Exposure:** 8501.

```dockerfile
FROM python:3.11-slim as base
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
USER appuser
HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health || exit 1
EXPOSE 8501
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
```

---

### 2. Kubernetes Cluster Orchestration
Production manifests in `k8s/` manage deployment, services, configuration, and autoscaling:
* **Deployment (`k8s/deployment.yaml`):** 2 initial pod replicas, rolling update strategy (`maxSurge: 1`, `maxUnavailable: 0`).
* **Service (`k8s/service.yaml`):** `LoadBalancer` exposing port 80 routing to internal port 8501.
* **Autoscaler (`k8s/hpa.yaml`):** Horizontal Pod Autoscaler dynamically scales from 2 to 6 pods based on CPU and ingress flow load.
* **ConfigMap (`k8s/configmap.yaml`):** Configures application environment variables and log thresholds.

---

### 3. Continuous Integration & Deployment (CI/CD)
Automated GitHub Actions workflow configured in `.github/workflows/ci.yml`:
1. **Code Checkout:** Uses `actions/checkout@v4`.
2. **Python Environment:** Sets up Python 3.11 with pip caching.
3. **Dependency Installation:** Installs `requirements.txt`.
4. **Code Quality Linting:** Flake8 syntax and PEP 8 verification.
5. **Pytest Automated Testing:** Runs 5 unit and functional tests with 100% pass rate.
6. **Docker Build Verification:** Builds container image to guarantee zero build failures.
