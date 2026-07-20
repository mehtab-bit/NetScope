# Stage 1: Build the C++ DPI engine
FROM gcc:11-bullseye AS cpp-builder
WORKDIR /build
COPY include/ ./include/
COPY src/ ./src/
RUN g++ -O3 -std=c++17 -Iinclude src/main.cpp src/pcap_reader.cpp src/packet_parser.cpp -o dpi_engine

# Stage 2: Final lightweight runner
FROM python:3.11-slim-bullseye
WORKDIR /app

# Copy python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy C++ compiled binary from Stage 1
COPY --from=cpp-builder /build/dpi_engine /app/dpi_engine

# Copy application assets
COPY backend/ ./backend/
COPY frontend/ ./frontend/

# Expose AWS App Runner default port
EXPOSE 8080
ENV PORT=8080
ENV HOST=0.0.0.0
ENV PYTHONPATH=/app

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8080"]
