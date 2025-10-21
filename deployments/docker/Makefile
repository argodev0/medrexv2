# Medrex DLT EMR Network Management Makefile

.PHONY: help network-up network-down network-restart clean-all setup-channel deploy-chaincode logs

# Default target
help:
	@echo "Medrex DLT EMR Network Management"
	@echo "================================="
	@echo "Available targets:"
	@echo "  network-up       - Start the Hyperledger Fabric network"
	@echo "  network-down     - Stop the network and remove containers"
	@echo "  network-restart  - Restart the entire network"
	@echo "  setup-channel    - Initialize channel and join peers"
	@echo "  clean-all        - Remove all containers, volumes, and crypto material"
	@echo "  deploy-chaincode - Deploy AccessPolicy and AuditLog chaincodes"
	@echo "  logs            - Show logs from all containers"
	@echo "  logs-orderer    - Show logs from orderer containers"
	@echo "  logs-peers      - Show logs from peer containers"

# Start the network
network-up:
	@echo "Starting Medrex DLT EMR Network..."
	docker-compose up -d
	@echo "Network started. Waiting for containers to be ready..."
	sleep 15
	@echo "Network is ready!"

# Stop the network
network-down:
	@echo "Stopping Medrex DLT EMR Network..."
	docker-compose down
	@echo "Network stopped."

# Restart the network
network-restart: network-down network-up

# Setup channel (run after network-up)
setup-channel:
	@echo "Setting up healthcare channel..."
	docker exec cli bash -c "cd /opt/gopath/src/github.com/hyperledger/fabric/peer && ./scripts/setup-network.sh"

# Clean everything
clean-all:
	@echo "Cleaning up all network artifacts..."
	docker-compose down -v --remove-orphans
	docker system prune -f
	sudo rm -rf crypto-config channel-artifacts
	@echo "Cleanup completed."

# Deploy chaincodes
deploy-chaincode:
	@echo "Deploying AccessPolicy and AuditLog chaincodes..."
	docker exec cli bash -c "cd /opt/gopath/src/github.com/hyperledger/fabric/peer && ./scripts/deploy-chaincode.sh"

# Show all logs
logs:
	docker-compose logs -f

# Show orderer logs
logs-orderer:
	docker-compose logs -f orderer1.medrex.com orderer2.medrex.com orderer3.medrex.com

# Show peer logs
logs-peers:
	docker-compose logs -f peer0.hospital.medrex.com peer1.hospital.medrex.com peer0.pharmacy.medrex.com peer1.pharmacy.medrex.com

# Quick start (full setup)
quick-start: network-up setup-channel
	@echo "Medrex DLT EMR Network is fully operational!"

# Development setup
dev-setup: clean-all network-up setup-channel
	@echo "Development environment ready!"