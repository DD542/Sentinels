FROM python:3.12-slim

WORKDIR /app

# Copie et installation des dépendances d'abord (cache Docker).
#
# Trois choses sont retirées dans la MÊME couche que leur installation —
# les supprimer plus tard ne ferait que les cacher, le contenu resterait
# dans l'historique de l'image :
#
#   * **les compilateurs** (gcc, g++) ne servent qu'à construire
#     certaines wheels. Un compilateur dans une image de production est à
#     la fois une surface d'attaque et la première chose que signale un
#     scanner ;
#   * **les listes de paquets APT et le cache pip**, sans usage au
#     runtime ;
#   * **pip lui-même** (voir ci-dessous).
#
# Retirer pip mérite une explication, parce que ce n'est pas courant.
#
# pip embarque ses propres dépendances (`pip/_vendor/`), et deux d'entre
# elles portaient des vulnérabilités HIGH corrigeables — msgpack 1.1.2
# (GHSA-6v7p-g79w-8964) et setuptools 70.3.0 (CVE-2025-47273). Elles ne
# viennent d'aucune de nos dépendances : mettre les nôtres à jour n'y
# change rien, seul le retrait de pip les fait disparaître. C'était la
# cause du seul échec restant du scan Trivy.
#
# Et c'est de toute façon un durcissement souhaitable : un conteneur de
# production n'a aucune raison de pouvoir installer des paquets. pip y
# est surtout le moyen le plus simple, pour un attaquant ayant obtenu
# l'exécution de code, de faire entrer son outillage.
COPY pyproject.toml ./
RUN apt-get update && apt-get install -y --no-install-recommends gcc g++ \
    && pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -e ".[detection,embeddings]" \
    && python -m spacy download fr_core_news_lg \
    && apt-get purge -y --auto-remove gcc g++ \
    && python -m pip uninstall -y pip \
    && rm -rf /var/lib/apt/lists/* /root/.cache \
             /usr/local/lib/python3.12/site-packages/pip*

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
