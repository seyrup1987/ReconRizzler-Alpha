# Stage 1: Use an official Python runtime as a parent image
FROM python:3.12

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
# Set a default DISPLAY environment variable for X11 forwarding.
ENV DISPLAY=:0

# Install uv (the new fast Python package installer from Astral)
RUN pip install uv

# Install system dependencies often required for GUI applications (e.g., X11 libraries for Dear PyGui)
# Dear PyGui typically relies on these standard X11 libraries.
RUN apt-get update && apt-get install -y \
    libx11-6 \
    libxext6 \
    libxrender1 \
    libxtst6 \
    libxi6 \
    fontconfig \
    libgl1-mesa-glx \
    libgl1-mesa-dri \
    libopengl0 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /app

# Copy the requirements.txt first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies using uv
RUN uv pip install -r requirements.txt --system

# Create the 'src' directory as expected by the font path in mcp_client_gui.py
RUN mkdir src

# Copy application files and folders into the container
# Place the 'fonts' directory inside 'src/'
COPY fonts ./src/fonts/

# WARNING: Copying the .env file directly into the image is generally not recommended
# if it contains sensitive information. Consider using 'docker run --env-file .env'
# or other methods to pass environment variables at runtime.
COPY .env .

# Copy Python scripts to the root of the working directory
COPY mcp_client_gui.py .
COPY models.py .
COPY ReConClient.py .
# requirements.txt is already copied and processed

# Define the command to run your GUI application
# This will run as root by default in the container.
CMD ["uv", "run", "mcp_client_gui.py"]