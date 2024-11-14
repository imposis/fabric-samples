#!/bin/bash

set -vx

# https://hyperledger-fabric.readthedocs.io/en/latest/private_data_tutorial.html#pd-use-case

# Setting environment variables
export PATH=${PWD}/../bin:${PWD}:$PATH
export FABRIC_CFG_PATH=$PWD/../config/
export CORE_PEER_TLS_ENABLED=true

# Network starting and deploying
cd ../test-network/
# counchdb is needed for private data
./network.sh up createChannel -ca -s couchdb

# Deploying chaincode
./network.sh deployCC -ccn private -ccp ../project-network/chaincode-go/ -ccl go -ccep "OR('Org2MSP.peer','Org2MSP.peer')" -cccg ../project-network/chaincode-go/collections_config.json

# Registering identities
export FABRIC_CA_CLIENT_HOME=${PWD}/organizations/peerOrganizations/org1.example.com
fabric-ca-client register --caname ca-org1 --id.name owner --id.secret ownerpw --id.type client --tls.certfiles "${PWD}/organizations/fabric-ca/org1/tls-cert.pem"
fabric-ca-client enroll -u https://owner:ownerpw@localhost:7054 --caname ca-org1 -M "${PWD}/organizations/peerOrganizations/org1.example.com/users/owner@org1.example.com/msp" --tls.certfiles "${PWD}/organizations/fabric-ca/org1/tls-cert.pem"
cp "${PWD}/organizations/peerOrganizations/org1.example.com/msp/config.yaml" "${PWD}/organizations/peerOrganizations/org1.example.com/users/owner@org1.example.com/msp/config.yaml"

export FABRIC_CA_CLIENT_HOME=${PWD}/organizations/peerOrganizations/org2.example.com/
fabric-ca-client register --caname ca-org2 --id.name buyer --id.secret buyerpw --id.type client --tls.certfiles "${PWD}/organizations/fabric-ca/org2/tls-cert.pem"
fabric-ca-client enroll -u https://buyer:buyerpw@localhost:8054 --caname ca-org2 -M "${PWD}/organizations/peerOrganizations/org2.example.com/users/buyer@org2.example.com/msp" --tls.certfiles "${PWD}/organizations/fabric-ca/org2/tls-cert.pem"
cp "${PWD}/organizations/peerOrganizations/org2.example.com/msp/config.yaml" "${PWD}/organizations/peerOrganizations/org2.example.com/users/buyer@org2.example.com/msp/config.yaml"

# Org1
export FABRIC_CA_CLIENT_HOME=${PWD}/organizations/peerOrganizations/org1.example.com
export CORE_PEER_LOCALMSPID=Org1MSP
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/owner@org1.example.com/msp
export CORE_PEER_ADDRESS=localhost:7051

# Example certificate creation
export CERT_PROPERTIES=$(echo -n "{ \"objectType\": \"certificate\", \"certificateId\": \"certificate1\", \"nameSurname\": \"John Doe\", \"certType\": \"IT\", \"certDescription\": \"IT certificate very nice\", \"validFrom\": \"2024-01-01\", \"validUntil\": \"2025-01-01\", \"UID\": \"990101/1234\" }" | base64 | tr -d \\n)
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n private -c '{"function":"CreateCertificate","Args":[]}' --transient "{\"certificate_properties\":\"$CERT_PROPERTIES\"}"

# Certificate query as Org1
peer chaincode query -C mychannel -n private -c '{"function":"ReadCertificate","Args":["certificate1"]}'
# Query private data as Org1
peer chaincode query -C mychannel -n private -c '{"function":"ReadCertificatePrivateDetails","Args":["Org1MSPPrivateCollection","certificate1"]}'

# Org2
export FABRIC_CA_CLIENT_HOME=${PWD}/organizations/peerOrganizations/org2.example.com/
export CORE_PEER_LOCALMSPID=Org2MSP
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org2.example.com/users/buyer@org2.example.com/msp
export CORE_PEER_ADDRESS=localhost:9051

# Certificate query as Org2
peer chaincode query -C mychannel -n private -c '{"function":"ReadCertificate","Args":["certificate1"]}'
# Checking if private data exist in Org2
peer chaincode query -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n private -c '{"function":"ReadCertificatePrivateDetails","Args":["Org2MSPPrivateCollection","certificate1"]}'
# Query private data as Org2
peer chaincode query -C mychannel -n private -c '{"function":"ReadCertificatePrivateDetails","Args":["Org1MSPPrivateCollection","certificate1"]}'

# Changing certificate validUntil
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n private -c '{"function":"ChangeCertificateValidUntil","Args":["certificate1", "2026-01-01"]}'
peer chaincode query -C mychannel -n private -c '{"function":"ReadCertificate","Args":["certificate1"]}'

# Org1
export FABRIC_CA_CLIENT_HOME=${PWD}/organizations/peerOrganizations/org1.example.com
export CORE_PEER_LOCALMSPID=Org1MSP
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/owner@org1.example.com/msp
export CORE_PEER_ADDRESS=localhost:7051

# Deleting certificate
export CERT_PROPERTIES=$(echo -n "{ \"certificateId\": \"certificate1\" }" | base64 | tr -d \\n)
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n private -c '{"function":"RemoveCertificate","Args":[]}' --transient "{ \"certificate_delete\": \"$CERT_PROPERTIES\" }" --peerAddresses localhost:7051 --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"

# Certificate query as Org1
peer chaincode query -C mychannel -n private -c '{"function":"ReadCertificate","Args":["certificate1"]}'
# Query private data as Org1
peer chaincode query -C mychannel -n private -c '{"function":"ReadCertificatePrivateDetails","Args":["Org1MSPPrivateCollection","certificate1"]}'
