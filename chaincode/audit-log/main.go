package main

import (
	"log"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/medrex/chaincode/audit-log/auditlog"
)

func main() {
	auditLogChaincode, err := contractapi.NewChaincode(&auditlog.SmartContract{})
	if err != nil {
		log.Panicf("Error creating AuditLog chaincode: %v", err)
	}

	if err := auditLogChaincode.Start(); err != nil {
		log.Panicf("Error starting AuditLog chaincode: %v", err)
	}
}