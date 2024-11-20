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
./network.sh deployCC -ccn private -ccp ../project-network/chaincode-go/ -ccl go -ccep "OR('Org1MSP.peer','Org2MSP.peer')" -cccg ../project-network/chaincode-go/collections_config.json

# Registering identities
# Org1 Admin
export FABRIC_CA_CLIENT_HOME=${PWD}/organizations/peerOrganizations/org1.example.com
fabric-ca-client register --caname ca-org1 --id.name org1admin --id.secret org1adminpw --id.type admin --tls.certfiles "${PWD}/organizations/fabric-ca/org1/tls-cert.pem"
fabric-ca-client enroll -u https://org1admin:org1adminpw@localhost:7054 --caname ca-org1 -M "${PWD}/organizations/peerOrganizations/org1.example.com/users/owner@org1.example.com/msp" --tls.certfiles "${PWD}/organizations/fabric-ca/org1/tls-cert.pem"
cp "${PWD}/organizations/peerOrganizations/org1.example.com/msp/config.yaml" "${PWD}/organizations/peerOrganizations/org1.example.com/users/org1admin@org1.example.com/msp/config.yaml"

# Org1 User
fabric-ca-client register --caname ca-org1 --id.name alice --id.secret alicepw --id.type client --tls.certfiles "${PWD}/organizations/fabric-ca/org1/tls-cert.pem"
fabric-ca-client enroll -u https://alice:alicepw@localhost:7054 --caname ca-org1 -M "${PWD}/organizations/peerOrganizations/org1.example.com/users/alice@org1.example.com/msp" --tls.certfiles "${PWD}/organizations/fabric-ca/org1/tls-cert.pem"
cp "${PWD}/organizations/peerOrganizations/org1.example.com/msp/config.yaml" "${PWD}/organizations/peerOrganizations/org1.example.com/users/alice@org1.example.com/msp/config.yaml"

# Org2 Admin
export FABRIC_CA_CLIENT_HOME=${PWD}/organizations/peerOrganizations/org2.example.com/
fabric-ca-client register --caname ca-org2 --id.name org2admin --id.secret org2adminpw --id.type admin --tls.certfiles "${PWD}/organizations/fabric-ca/org2/tls-cert.pem"
fabric-ca-client enroll -u https://org2admin:org2adminpw@localhost:8054 --caname ca-org2 -M "${PWD}/organizations/peerOrganizations/org2.example.com/users/org2admin@org2.example.com/msp" --tls.certfiles "${PWD}/organizations/fabric-ca/org2/tls-cert.pem"
cp "${PWD}/organizations/peerOrganizations/org2.example.com/msp/config.yaml" "${PWD}/organizations/peerOrganizations/org2.example.com/users/org2admin@org2.example.com/msp/config.yaml"

# Org2 User
export FABRIC_CA_CLIENT_HOME=${PWD}/organizations/peerOrganizations/org2.example.com/
fabric-ca-client register --caname ca-org2 --id.name bob --id.secret bobpw --id.type client --tls.certfiles "${PWD}/organizations/fabric-ca/org2/tls-cert.pem"
fabric-ca-client enroll -u https://bob:bobpw@localhost:8054 --caname ca-org2 -M "${PWD}/organizations/peerOrganizations/org2.example.com/users/bob@org2.example.com/msp" --tls.certfiles "${PWD}/organizations/fabric-ca/org2/tls-cert.pem"
cp "${PWD}/organizations/peerOrganizations/org2.example.com/msp/config.yaml" "${PWD}/organizations/peerOrganizations/org2.example.com/users/bob@org2.example.com/msp/config.yaml"

# Org1 Admin
export FABRIC_CA_CLIENT_HOME=${PWD}/organizations/peerOrganizations/org1.example.com
export CORE_PEER_LOCALMSPID=Org1MSP
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/org1admin@org1.example.com/msp
export CORE_PEER_ADDRESS=localhost:7051

# Example certificate creation
export CERT_PROPERTIES=$(echo -n "{ \"objectType\": \"certificate\", \"certificateId\": \"certificate1\", \"nameSurname\": \"John Doe\", \"certType\": \"IT\", \"certDescription\": \"IT certificate very nice\", \"validFrom\": \"2024-01-01\", \"validUntil\": \"2025-01-01\", \"UID\": \"990101/1234\" }" | base64 | tr -d \\n)
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n private -c '{"function":"CreateCertificate","Args":[]}' --transient "{\"certificate_properties\":\"$CERT_PROPERTIES\"}"

sleep 2

# Certificate query as Org1
peer chaincode query -C mychannel -n private -c '{"function":"ReadCertificate","Args":["certificate1"]}'
sleep 2

# Query private data as Org1
peer chaincode query -C mychannel -n private -c '{"function":"ReadCertificatePrivateDetails","Args":["Org1MSPPrivateCollection","certificate1"]}'
sleep 2

# Org2 Admin
export FABRIC_CA_CLIENT_HOME=${PWD}/organizations/peerOrganizations/org2.example.com/
export CORE_PEER_LOCALMSPID=Org2MSP
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org2.example.com/users/org2admin@org2.example.com/msp
export CORE_PEER_ADDRESS=localhost:9051

# Certificate query as Org2
peer chaincode query -C mychannel -n private -c '{"function":"ReadCertificate","Args":["certificate1"]}'
sleep 2
# Checking if private data exist in Org2
peer chaincode query -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n private -c '{"function":"ReadCertificatePrivateDetails","Args":["Org2MSPPrivateCollection","certificate1"]}'
sleep 2
# Query private data as Org2
peer chaincode query -C mychannel -n private -c '{"function":"ReadCertificatePrivateDetails","Args":["Org1MSPPrivateCollection","certificate1"]}'
sleep 2

# Changing certificate validUntil
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n private -c '{"function":"ChangeCertificateValidUntil","Args":["certificate1", "2026-01-01"]}'
sleep 2
peer chaincode query -C mychannel -n private -c '{"function":"ReadCertificate","Args":["certificate1"]}'
sleep 2

# Org1
export FABRIC_CA_CLIENT_HOME=${PWD}/organizations/peerOrganizations/org1.example.com
export CORE_PEER_LOCALMSPID=Org1MSP
export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/org1admin@org1.example.com/msp
export CORE_PEER_ADDRESS=localhost:7051

# Deleting certificate
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n private -c '{"function":"RemoveCertificate","Args":["certificate1"]}' --peerAddresses localhost:7051 --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
sleep 2

# Certificate query as Org1
peer chaincode query -C mychannel -n private -c '{"function":"ReadCertificate","Args":["certificate1"]}'
sleep 2
# Query private data as Org1
peer chaincode query -C mychannel -n private -c '{"function":"ReadCertificatePrivateDetails","Args":["Org1MSPPrivateCollection","certificate1"]}'
sleep 2
