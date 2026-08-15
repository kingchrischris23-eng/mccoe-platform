FROM kalilinux/kali-rolling

# First build takes 10-20 min (Metasploit is ~2GB).
# After that Docker caches it — restarts are instant.

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -y && apt-get install -y \
    metasploit-framework \
    nmap \
    hydra \
    sqlmap \
    nikto \
    gobuster \
    netcat-openbsd \
    curl \
    wget \
    git \
    python3 \
    python3-pip \
    wordlists \
    ttyd \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create working directories for student notes and reports
RUN mkdir -p /root/lab/reports /root/lab/scans /root/lab/notes

# Welcome message shown every time a terminal opens
COPY motd.txt /etc/motd
RUN echo 'cat /etc/motd' >> /root/.bashrc && \
    echo 'alias ll="ls -la"' >> /root/.bashrc && \
    echo 'alias ms2="msfconsole -q"' >> /root/.bashrc && \
    echo 'cd /root/lab' >> /root/.bashrc

EXPOSE 7681

CMD ["ttyd", "--port", "7681", "--writable", "bash"]
