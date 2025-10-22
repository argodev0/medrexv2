#!/bin/bash

# Medrex DLT EMR Services Stop Script
# This script stops all running microservices

set -e

echo "🛑 Stopping Medrex DLT EMR Services..."

# Function to stop a service
stop_service() {
    local service_name=$1
    local pid_file="logs/${service_name}.pid"
    
    if [ -f "$pid_file" ]; then
        local pid=$(cat "$pid_file")
        if ps -p $pid > /dev/null 2>&1; then
            echo "🔄 Stopping ${service_name} (PID: $pid)..."
            kill $pid
            
            # Wait for the process to stop
            local count=0
            while ps -p $pid > /dev/null 2>&1 && [ $count -lt 10 ]; do
                sleep 1
                count=$((count + 1))
            done
            
            if ps -p $pid > /dev/null 2>&1; then
                echo "⚠️  Force killing ${service_name}..."
                kill -9 $pid
            fi
            
            echo "✅ ${service_name} stopped"
        else
            echo "⚠️  ${service_name} was not running"
        fi
        rm -f "$pid_file"
    else
        echo "⚠️  No PID file found for ${service_name}"
    fi
}

# Stop services in reverse order
echo "🏥 Stopping Medrex DLT EMR Microservices..."
echo ""

stop_service "API Gateway"
stop_service "Mobile Workflow Service"
stop_service "Scheduling Service"
stop_service "Clinical Notes Service"
stop_service "IAM Service"

echo ""
echo "🎉 All Medrex DLT EMR services have been stopped!"
echo ""
echo "📝 Log files are preserved in the 'logs/' directory"