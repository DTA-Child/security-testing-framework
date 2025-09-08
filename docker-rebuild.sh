#!/bin/bash
# Docker rebuild script for Security Testing Framework

echo "🐳 Docker Rebuild - Security Testing Framework"
echo "=============================================="

# Stop and remove existing containers
echo "🛑 Stopping existing containers..."
docker-compose down -v 2>/dev/null || true

# Remove old images (optional - uncomment if needed)
# echo "🗑️ Removing old images..."
# docker rmi $(docker images "webapp*" -q) 2>/dev/null || true

# Build and start new containers
echo "🔨 Building new containers..."
docker-compose build --no-cache

echo "🚀 Starting services..."
docker-compose up -d

# Wait for services to start
echo "⏳ Waiting for services to start..."
sleep 10

# Check container status
echo "📊 Container Status:"
docker-compose ps

# Check application health
echo ""
echo "🔍 Testing application health..."
if curl -s http://localhost:8000/api/health > /dev/null 2>&1; then
    echo "✅ Application is running successfully!"
    echo "🌐 Web Interface: http://localhost:8000"
    echo "📊 API Documentation: http://localhost:8000/docs"
else
    echo "❌ Application health check failed"
    echo "📋 Check logs with: docker-compose logs app"
fi

echo ""
echo "🔧 Useful commands:"
echo "   View logs: docker-compose logs -f app"
echo "   Stop services: docker-compose down"
echo "   Restart: docker-compose restart"