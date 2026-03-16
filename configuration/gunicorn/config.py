import multiprocessing

# Server socket
bind = "unix:/run/gunicorn/main.sock"

# Worker processes
workers = 2 * multiprocessing.cpu_count() + 1
max_requests = 1000
max_requests_jitter = 50

# Protocol
protocol = "uwsgi"

# Server mechanics
preload_app = True
graceful_timeout = 30
timeout = 120
pidfile = "/run/gunicorn/gunicorn.pid"

# Logging
accesslog = "/var/log/greedybear/gunicorn/access.log"
errorlog = "/var/log/greedybear/gunicorn/error.log"
