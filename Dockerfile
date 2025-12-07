# Use Ubuntu as the base image
FROM ubuntu:latest

# Avoid prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update and install necessary packages
# - build-essential: contains gcc, make, etc.
# - libpcap-dev: library for packet capture
# - net-tools: for ifconfig etc.
# - curl/wget/telnet: for generating traffic
# - nano/vim: for editing files if needed
RUN apt-get update && apt-get install -y \
    build-essential \
    libpcap-dev \
    net-tools \
    iputils-ping \
    curl \
    telnet \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Compile the projects automatically upon build
RUN gcc -o analysis analysis.c
RUN gcc -o sniffer sniffer.c -lpcap

# Default command: just start a bash shell
CMD ["/bin/bash"]
