FROM python:3.12-slim

# Dépendances système minimales (spaCy/Presidio ont besoin de gcc pour certaines wheels)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copie et installation des dépendances d'abord (cache Docker)
COPY pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -e ".[detection,embeddings]"

# Modèle spaCy français (couche L2)
RUN python -m spacy download fr_core_news_lg

# Copie du code
COPY app ./app
COPY tests ./tests

# Utilisateur non-root (bonne pratique sécurité)
RUN useradd -m -u 1000 sentinel && chown -R sentinel:sentinel /app
USER sentinel

EXPOSE 8000

# Healthcheck : Docker sait si le service est vivant
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health').raise_for_status()"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
