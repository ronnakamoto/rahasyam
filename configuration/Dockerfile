FROM nginx:latest

COPY ./configuration/trust/ZscalerRootCertificate-2048-SHA256-Feb2025.pem /usr/local/share/ca-certificates/zscaler-root-feb2025.crt
RUN chmod 644 /usr/local/share/ca-certificates/zscaler-root-feb2025.crt && update-ca-certificates || true

# Remove default nginx config so only ours is used
RUN rm /etc/nginx/conf.d/default.conf

# Create config directory
RUN mkdir -p /var/www/html/configuration/toml 

# Copy our nginx config
COPY ./configuration/nginx.conf /etc/nginx/conf.d/default.conf

# Copy static files (if any go into /var/www/html/bin)
# Directory copy tolerates the PLONK `proving_key` being absent (e.g. Nova-only
# setups, which are the docker default). The directory always exists in the
# build context via its tracked placeholder; any generated keys are included.
COPY ./configuration/bin/keys/ /var/www/html/

RUN chown -R nginx:nginx /var/www/html \     
    && chmod -R 755 /var/www/html  

CMD ["nginx", "-g", "daemon off;"]

