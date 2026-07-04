# PhishingShield Deployment Guide

## Production Setup

PhishingShield is deployed as a FastAPI web application.

### Docker Deployment

To build and run the production container:
```bash
docker build -t phishing-shield -f docker/Dockerfile .
docker run -p 8000:8000 phishing-shield
```

### Redis Caching

Ensure a Redis instance is active to cache queries and reduce detection latency for repeat lookups.
