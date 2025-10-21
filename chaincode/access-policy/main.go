package main

import (
	"log"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/medrex/chaincode/access-policy/accesspolicy"
)

func main() {
	accessPolicyChaincode, err := contractapi.NewChaincode(&accesspolicy.SmartContract{})
	if err != nil {
		log.Panicf("Error creating AccessPolicy chaincode: %v", err)
	}

	if err := accessPolicyChaincode.Start(); err != nil {
		log.Panicf("Error starting AccessPolicy chaincode: %v", err)
	}
}