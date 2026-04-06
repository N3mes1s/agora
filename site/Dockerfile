FROM nginx:alpine
COPY index.html /usr/share/nginx/html/index.html
COPY install.sh /usr/share/nginx/html/install
RUN echo 'server { listen 8080; root /usr/share/nginx/html; location /install { default_type text/plain; } }' > /etc/nginx/conf.d/default.conf
EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
