#!/bin/bash
# Medrex DLT EMR Network Setup Script
# Generates crypto material, creates channel artifacts, and initializes the network

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
CHANNEL_NAME="healthcare"
ORDERER_CA=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config/ordererOrganizations/medrex.com/orderers/orderer1.medrex.com/msp/tlscacerts/tlsca.medrex.com-cert.pem

echo -e "${GREEN}Starting Medrex DLT EMR Network Setup...${NC}"

# Function to print status
print_status() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

# Function to print success
print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Function to print error
print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Generate crypto material
generate_crypto() {
    print_status "Generating crypto material..."
    
    if [ -d "crypto-config" ]; then
        rm -rf crypto-config
    fi
    
    cryptogen generate --config=./crypto-config.yaml
    
    if [ $? -eq 0 ]; then
        print_success "Crypto material generated successfully"
    else
        print_error "Failed to generate crypto material"
        exit 1
    fi
}

# Generate channel artifacts
generate_channel_artifacts() {
    print_status "Generating channel artifacts..."
    
    if [ -d "channel-artifacts" ]; then
        rm -rf channel-artifacts
    fi
    mkdir channel-artifacts
    
    # Generate genesis block
    print_status "Generating genesis block..."
    configtxgen -profile MedrexOrdererGenesis -channelID system-channel -outputBlock ./channel-artifacts/genesis.block
    
    # Generate channel configuration transaction
    print_status "Generating channel configuration transaction..."
    configtxgen -profile HealthcareChannel -outputCreateChannelTx ./channel-artifacts/${CHANNEL_NAME}.tx -channelID $CHANNEL_NAME
    
    # Generate anchor peer transactions
    print_status "Generating anchor peer transactions..."
    configtxgen -profile HealthcareChannel -outputAnchorPeersUpdate ./channel-artifacts/HospitalMSPanchors.tx -channelID $CHANNEL_NAME -asOrg HospitalMSP
    configtxgen -profile HealthcareChannel -outputAnchorPeersUpdate ./channel-artifacts/PharmacyMSPanchors.tx -channelID $CHANNEL_NAME -asOrg PharmacyMSP
    
    print_success "Channel artifacts generated successfully"
}

# Create channel
create_channel() {
    print_status "Creating channel: $CHANNEL_NAME"
    
    # Set environment for Hospital peer
    export CORE_PEER_LOCALMSPID="HospitalMSP"
    export CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config/peerOrganizations/hospital.medrex.com/peers/peer0.hospital.medrex.com/tls/ca.crt
    export CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config/peerOrganizations/hospital.medrex.com/users/Admin@hospital.medrex.com/msp
    export CORE_PEER_ADDRESS=peer0.hospital.medrex.com:7051
    
    peer channel create -o orderer1.medrex.com:7050 -c $CHANNEL_NAME -f ./channel-artifacts/${CHANNEL_NAME}.tx --tls --cafile $ORDERER_CA
    
    print_success "Channel created successfully"
}

# Join peers to channel
join_peers() {
    print_status "Joining peers to channel..."
    
    # Join Hospital peers
    print_status "Joining Hospital peers..."
    export CORE_PEER_LOCALMSPID="HospitalMSP"
    export CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config/peerOrganizations/hospital.medrex.com/peers/peer0.hospital.medrex.com/tls/ca.crt
    export CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config/peerOrganizations/hospital.medrex.com/users/Admin@hospital.medrex.com/msp
    
    # Join peer0.hospital
    export CORE_PEER_ADDRESS=peer0.hospital.medrex.com:7051
    peer channel join -b ${CHANNEL_NAME}.block
    
    # Join peer1.hospital
    export CORE_PEER_ADDRESS=peer1.hospital.medrex.com:8051
    peer channel join -b ${CHANNEL_NAME}.block
    
    # Join Pharmacy peers
    print_status "Joining Pharmacy peers..."
    export CORE_PEER_LOCALMSPID="PharmacyMSP"
    export CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config/peerOrganizations/pharmacy.medrex.com/peers/peer0.pharmacy.medrex.com/tls/ca.crt
    export CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config/peerOrganizations/pharmacy.medrex.com/users/Admin@pharmacy.medrex.com/msp
    
    # Join peer0.pharmacy
    export CORE_PEER_ADDRESS=peer0.pharmacy.medrex.com:9051
    peer channel join -b ${CHANNEL_NAME}.block
    
    # Join peer1.pharmacy
    export CORE_PEER_ADDRESS=peer1.pharmacy.medrex.com:10051
    peer channel join -b ${CHANNEL_NAME}.block
    
    print_success "All peers joined channel successfully"
}

# Update anchor peers
update_anchor_peers() {
    print_status "Updating anchor peers..."
    
    # Update Hospital anchor peer
    export CORE_PEER_LOCALMSPID="HospitalMSP"
    export CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config/peerOrganizations/hospital.medrex.com/peers/peer0.hospital.medrex.com/tls/ca.crt
    export CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config/peerOrganizations/hospital.medrex.com/users/Admin@hospital.medrex.com/msp
    export CORE_PEER_ADDRESS=peer0.hospital.medrex.com:7051
    
    peer channel update -o orderer1.medrex.com:7050 -c $CHANNEL_NAME -f ./channel-artifacts/HospitalMSPanchors.tx --tls --cafile $ORDERER_CA
    
    # Update Pharmacy anchor peer
    export CORE_PEER_LOCALMSPID="PharmacyMSP"
    export CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config/peerOrganizations/pharmacy.medrex.com/peers/peer0.pharmacy.medrex.com/tls/ca.crt
    export CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config/peerOrganizations/pharmacy.medrex.com/users/Admin@pharmacy.medrex.com/msp
    export CORE_PEER_ADDRESS=peer0.pharmacy.medrex.com:9051
    
    peer channel update -o orderer1.medrex.com:7050 -c $CHANNEL_NAME -f ./channel-artifacts/PharmacyMSPanchors.tx --tls --cafile $ORDERER_CA
    
    print_success "Anchor peers updated successfully"
}

# Main execution
main() {
    print_status "Medrex DLT EMR Network Setup Starting..."
    
    generate_crypto
    generate_channel_artifacts
    
    # Wait for network to be ready
    print_status "Waiting for network to be ready..."
    sleep 10
    
    create_channel
    join_peers
    update_anchor_peers
    
    print_success "Medrex DLT EMR Network setup completed successfully!"
    print_status "Channel: $CHANNEL_NAME is ready for chaincode deployment"
}

# Execute main function
main "$@"