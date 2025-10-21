#!/bin/bash
# Medrex DLT EMR Chaincode Deployment Script
# Deploys AccessPolicy and AuditLog chaincodes to the healthcare channel

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
CHANNEL_NAME="healthcare"
CHAINCODE_VERSION="1.0"
SEQUENCE=1
ORDERER_CA=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config/ordererOrganizations/medrex.com/orderers/orderer1.medrex.com/msp/tlscacerts/tlsca.medrex.com-cert.pem

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

# Set environment for Hospital peer
set_hospital_env() {
    export CORE_PEER_LOCALMSPID="HospitalMSP"
    export CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config/peerOrganizations/hospital.medrex.com/peers/peer0.hospital.medrex.com/tls/ca.crt
    export CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config/peerOrganizations/hospital.medrex.com/users/Admin@hospital.medrex.com/msp
    export CORE_PEER_ADDRESS=peer0.hospital.medrex.com:7051
}

# Set environment for Pharmacy peer
set_pharmacy_env() {
    export CORE_PEER_LOCALMSPID="PharmacyMSP"
    export CORE_PEER_TLS_ROOTCERT_FILE=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config/peerOrganizations/pharmacy.medrex.com/peers/peer0.pharmacy.medrex.com/tls/ca.crt
    export CORE_PEER_MSPCONFIGPATH=/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config/peerOrganizations/pharmacy.medrex.com/users/Admin@pharmacy.medrex.com/msp
    export CORE_PEER_ADDRESS=peer0.pharmacy.medrex.com:9051
}

# Package chaincode
package_chaincode() {
    local chaincode_name=$1
    local chaincode_path=$2
    
    print_status "Packaging $chaincode_name chaincode..."
    
    peer lifecycle chaincode package ${chaincode_name}.tar.gz \
        --path $chaincode_path \
        --lang golang \
        --label ${chaincode_name}_${CHAINCODE_VERSION}
    
    if [ $? -eq 0 ]; then
        print_success "$chaincode_name chaincode packaged successfully"
    else
        print_error "Failed to package $chaincode_name chaincode"
        exit 1
    fi
}

# Install chaincode on peer
install_chaincode() {
    local chaincode_name=$1
    local org_name=$2
    
    print_status "Installing $chaincode_name chaincode on $org_name..."
    
    peer lifecycle chaincode install ${chaincode_name}.tar.gz
    
    if [ $? -eq 0 ]; then
        print_success "$chaincode_name chaincode installed on $org_name"
    else
        print_error "Failed to install $chaincode_name chaincode on $org_name"
        exit 1
    fi
}

# Query installed chaincode to get package ID
query_installed() {
    local chaincode_name=$1
    
    print_status "Querying installed chaincode: $chaincode_name"
    
    peer lifecycle chaincode queryinstalled --output json | jq -r ".installed_chaincodes[] | select(.label==\"${chaincode_name}_${CHAINCODE_VERSION}\") | .package_id"
}

# Approve chaincode for organization
approve_chaincode() {
    local chaincode_name=$1
    local package_id=$2
    local org_name=$3
    
    print_status "Approving $chaincode_name chaincode for $org_name..."
    
    peer lifecycle chaincode approveformyorg \
        -o orderer1.medrex.com:7050 \
        --channelID $CHANNEL_NAME \
        --name $chaincode_name \
        --version $CHAINCODE_VERSION \
        --package-id $package_id \
        --sequence $SEQUENCE \
        --tls \
        --cafile $ORDERER_CA
    
    if [ $? -eq 0 ]; then
        print_success "$chaincode_name chaincode approved for $org_name"
    else
        print_error "Failed to approve $chaincode_name chaincode for $org_name"
        exit 1
    fi
}

# Commit chaincode to channel
commit_chaincode() {
    local chaincode_name=$1
    
    print_status "Committing $chaincode_name chaincode to channel..."
    
    peer lifecycle chaincode commit \
        -o orderer1.medrex.com:7050 \
        --channelID $CHANNEL_NAME \
        --name $chaincode_name \
        --version $CHAINCODE_VERSION \
        --sequence $SEQUENCE \
        --tls \
        --cafile $ORDERER_CA \
        --peerAddresses peer0.hospital.medrex.com:7051 \
        --tlsRootCertFiles /opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config/peerOrganizations/hospital.medrex.com/peers/peer0.hospital.medrex.com/tls/ca.crt \
        --peerAddresses peer0.pharmacy.medrex.com:9051 \
        --tlsRootCertFiles /opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config/peerOrganizations/pharmacy.medrex.com/peers/peer0.pharmacy.medrex.com/tls/ca.crt
    
    if [ $? -eq 0 ]; then
        print_success "$chaincode_name chaincode committed to channel"
    else
        print_error "Failed to commit $chaincode_name chaincode to channel"
        exit 1
    fi
}

# Initialize chaincode
init_chaincode() {
    local chaincode_name=$1
    
    print_status "Initializing $chaincode_name chaincode..."
    
    peer chaincode invoke \
        -o orderer1.medrex.com:7050 \
        --tls \
        --cafile $ORDERER_CA \
        -C $CHANNEL_NAME \
        -n $chaincode_name \
        --peerAddresses peer0.hospital.medrex.com:7051 \
        --tlsRootCertFiles /opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config/peerOrganizations/hospital.medrex.com/peers/peer0.hospital.medrex.com/tls/ca.crt \
        --peerAddresses peer0.pharmacy.medrex.com:9051 \
        --tlsRootCertFiles /opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config/peerOrganizations/pharmacy.medrex.com/peers/peer0.pharmacy.medrex.com/tls/ca.crt \
        -c '{"function":"InitLedger","Args":[]}'
    
    if [ $? -eq 0 ]; then
        print_success "$chaincode_name chaincode initialized"
    else
        print_error "Failed to initialize $chaincode_name chaincode"
        exit 1
    fi
}

# Deploy a single chaincode
deploy_single_chaincode() {
    local chaincode_name=$1
    local chaincode_path=$2
    
    print_status "Deploying $chaincode_name chaincode..."
    
    # Package chaincode
    package_chaincode $chaincode_name $chaincode_path
    
    # Install on Hospital org
    set_hospital_env
    install_chaincode $chaincode_name "Hospital"
    PACKAGE_ID=$(query_installed $chaincode_name)
    approve_chaincode $chaincode_name $PACKAGE_ID "Hospital"
    
    # Install on Pharmacy org
    set_pharmacy_env
    install_chaincode $chaincode_name "Pharmacy"
    approve_chaincode $chaincode_name $PACKAGE_ID "Pharmacy"
    
    # Commit chaincode (can be done from any org)
    set_hospital_env
    commit_chaincode $chaincode_name
    
    # Initialize chaincode
    init_chaincode $chaincode_name
    
    print_success "$chaincode_name chaincode deployment completed!"
}

# Main deployment function
main() {
    print_status "Starting Medrex DLT EMR Chaincode Deployment..."
    
    # Check if channel exists
    print_status "Checking channel status..."
    set_hospital_env
    peer channel list
    
    # Deploy AccessPolicy chaincode
    deploy_single_chaincode "accesspolicy" "/opt/gopath/src/github.com/hyperledger/fabric/peer/chaincode/access-policy"
    
    # Deploy AuditLog chaincode
    deploy_single_chaincode "auditlog" "/opt/gopath/src/github.com/hyperledger/fabric/peer/chaincode/audit-log"
    
    print_success "All chaincodes deployed successfully!"
    
    # Test chaincode functionality
    print_status "Testing chaincode functionality..."
    
    # Test AccessPolicy chaincode
    print_status "Testing AccessPolicy chaincode..."
    peer chaincode query -C $CHANNEL_NAME -n accesspolicy -c '{"Args":["GetAccessPolicy","policy_patient_ehr"]}'
    
    # Test AuditLog chaincode
    print_status "Testing AuditLog chaincode..."
    peer chaincode invoke \
        -o orderer1.medrex.com:7050 \
        --tls \
        --cafile $ORDERER_CA \
        -C $CHANNEL_NAME \
        -n auditlog \
        --peerAddresses peer0.hospital.medrex.com:7051 \
        --tlsRootCertFiles /opt/gopath/src/github.com/hyperledger/fabric/peer/crypto-config/peerOrganizations/hospital.medrex.com/peers/peer0.hospital.medrex.com/tls/ca.crt \
        -c '{"function":"LogUserLogin","Args":["test_user","consulting_doctor","192.168.1.100","TestAgent","true"]}'
    
    print_success "Chaincode testing completed!"
    print_success "Medrex DLT EMR chaincodes are ready for use!"
}

# Execute main function
main "$@"