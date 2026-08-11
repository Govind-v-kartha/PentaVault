# ---------- Stage 1: Build the React/Vite frontend ----------
FROM node:20-slim AS frontend-build

WORKDIR /app/frontend
COPY scanner/web/frontend/package*.json ./
RUN npm install

COPY scanner/web/frontend/ ./
RUN npm run build
# Output lands in /app/frontend/dist


# ---------- Stage 2: Python runtime with Playwright pre-installed ----------
FROM mcr.microsoft.com/playwright/python:v1.45.0-jammy

WORKDIR /app

# Install Python deps first (better layer caching — only reruns if requirements.txt changes)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Playwright browsers are already installed in this base image.
# If requirements.txt pins a different playwright version, update the
# base image tag above (v1.45.0-jammy) to match.

# Copy the rest of the application code
COPY . .

# Overwrite static/ with the freshly built frontend from Stage 1 and populate frontend/dist/
RUN rm -rf scanner/web/static/* && mkdir -p scanner/web/frontend/dist
COPY --from=frontend-build /app/frontend/dist/ scanner/web/static/
COPY --from=frontend-build /app/frontend/dist/ scanner/web/frontend/dist/


EXPOSE 8000

CMD uvicorn scanner.web.app:app --host 0.0.0.0 --port ${PORT:-8000}
