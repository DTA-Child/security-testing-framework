FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies (including WeasyPrint dependencies)
RUN apt-get update && apt-get install -y \
    wget \
    curl \
    unzip \
    git \
    build-essential \
    libxml2-dev \
    libxslt1-dev \
    libffi-dev \
    libssl-dev \
    libgtk-3-dev \
    libglib2.0-0 \
    libcairo2 \
    pango1.0-tools \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-xlib-2.0-0 \
    libgobject-2.0-0 \
    shared-mime-info \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*



# Install Nuclei
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v2.9.4/nuclei_2.9.4_linux_amd64.zip \
    && unzip nuclei_2.9.4_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei_2.9.4_linux_amd64.zip

# Install Nikto
RUN git clone https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /usr/local/bin/nikto

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create reports directory
RUN mkdir -p reports

# Expose port
EXPOSE 8000

# Set environment variables
ENV PYTHONPATH=/app
ENV ZAP_HOST=zap
ENV API_HOST=0.0.0.0
ENV API_PORT=8000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 CMD curl -f http://localhost:8000/api/health || exit 1

# Run the application
CMD ["python", "main.py"]
