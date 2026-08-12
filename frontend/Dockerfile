# Étape 1 : build
FROM node:20-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

# Étape 2 : service statique léger.
#
# Image *unprivileged* : elle tourne en UID 101 sans capacité root et
# écoute sur 8080. L'image nginx standard démarre en root, ce qui est
# incompatible avec `runAsNonRoot` — la posture d'exécution imposée au
# backend doit valoir pour la console aussi.
FROM nginxinc/nginx-unprivileged:alpine
# L'entrypoint applique envsubst aux gabarits, puis les dépose dans
# conf.d : le nom d'hôte du backend n'est plus figé dans l'image.
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
ENV SENTINEL_API_UPSTREAM=http://backend:8000
# Renseigne NGINX_LOCAL_RESOLVERS depuis /etc/resolv.conf du conteneur.
# Sans ce drapeau, la variable reste vide et nginx refuse de démarrer :
# le résolveur est indispensable dès lors que l'hôte amont est résolu à
# chaque requête plutôt qu'au chargement de la configuration.
ENV NGINX_ENTRYPOINT_LOCAL_RESOLVERS=1
EXPOSE 8080
