# Common proxy routes for DevCollab (Included by HTTP and HTTPS server blocks)

# Security Headers
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

client_max_body_size 1m;
limit_conn conn_limit 50;

# 1. Real-Time Socket.IO WebSocket Ingress
location /socket.io/ {
    proxy_pass http://backend_nodes;
    proxy_http_version 1.1;

    # Critical WebSocket Upgrade Headers
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";

    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    # Maintain persistent WebSocket connection without dropouts
    proxy_read_timeout 86400s;
    proxy_send_timeout 86400s;
    proxy_buffering off;
}

# 2. Express REST API Ingress
location /api/ {
    limit_req zone=api_limit burst=20 nodelay;

    proxy_pass http://backend_nodes;
    proxy_http_version 1.1;

    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    proxy_read_timeout 30s;
    proxy_connect_timeout 5s;
}

# 3. Static Frontend SPA Ingress
location / {
    proxy_pass http://frontend_nodes;
    proxy_http_version 1.1;

    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
