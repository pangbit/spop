FROM haproxy:latest

# Switch to root to install packages
User root
RUN apt-get update && apt-get install -y iproute2 netcat-traditional && rm -rf /var/lib/apt/lists/*

User haproxy

# Copy HAProxy and SPOE configuration files
COPY haproxy.cfg /usr/local/etc/haproxy/haproxy.cfg
COPY spoe-test.conf /usr/local/etc/haproxy/spoe-test.conf

# Set up HAProxy to run in the foreground
CMD ["haproxy", "-d", "-f", "/usr/local/etc/haproxy/haproxy.cfg", "-db"]
