# Stage 1: Use an official Python runtime as a parent image
FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV HF_HOME="/app/.hf_cache/huggingface"
ENV SENTENCE_TRANSFORMERS_HOME="/app/.hf_cache/sentence_transformers"
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies including curl, nmap, Google Chrome, and unzip
RUN apt-get update && \
    apt-get install -y curl nmap wget gnupg unzip --no-install-recommends && \
    # Add Google Chrome
    wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - && \
    sh -c 'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list' && \
    apt-get update && \
    apt-get install -y google-chrome-stable --no-install-recommends && \
    # Clean up apt cache
    rm -rf /var/lib/apt/lists/* && \
    apt-get clean

# Install uv, a rust-based python package installer
RUN pip install uv

# Set the working directory in the container
WORKDIR /app

# Copy the requirements.txt first to leverage Docker cache
COPY requirements.txt .

# Install any needed packages specified in requirements.txt using uv
# WebDriverManager will be installed as part of these requirements if it's listed.
RUN uv pip install -r requirements.txt --system

# Copy the model preloader script
COPY preload_model.py .

# Run the preloader script to download and cache the model
# This happens during the image build process.
RUN python preload_model.py

# Copy the rest of the application's code into the container
COPY . .

# Expose the port the app runs on
EXPOSE 8000

# Define the command to run your application
CMD ["uv", "run", "Rizzler.py"]