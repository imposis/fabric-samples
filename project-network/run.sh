#!/bin/bash

set -vx

# https://hyperledger-fabric.readthedocs.io/en/latest/private_data_tutorial.html#pd-use-case

# Setting environment variables
export PATH=${PWD}/../bin:${PWD}:$PATH; export FABRIC_CFG_PATH=$PWD/../config/; export CORE_PEER_TLS_ENABLED=true;

# Network starting and deploying
cd ../test-network/
# counchdb is needed for private data
./network.sh up createChannel -ca -s couchdb

# Deploying chaincode
./network.sh deployCC -ccn private -ccp ../project-network/chaincode-go/ -ccl go -ccep "OR('Org1MSP.peer','Org2MSP.peer')" -cccg ../project-network/chaincode-go/collections_config.json

# Registering identities
export FABRIC_CA_CLIENT_HOME=${PWD}/organizations/peerOrganizations/org1.example.com; fabric-ca-client register --caname ca-org1 --id.name groot --id.secret grootpw --id.type admin --id.attrs "role=admin:ecert,org=org1:ecert" --tls.certfiles "${PWD}/organizations/fabric-ca/org1/tls-cert.pem"; fabric-ca-client enroll -u https://groot:grootpw@localhost:7054 --caname ca-org1 -M "${PWD}/organizations/peerOrganizations/org1.example.com/users/groot@org1.example.com/msp" --tls.certfiles "${PWD}/organizations/fabric-ca/org1/tls-cert.pem"; cp "${PWD}/organizations/peerOrganizations/org1.example.com/msp/config.yaml" "${PWD}/organizations/peerOrganizations/org1.example.com/users/groot@org1.example.com/msp/config.yaml";

# Org1
export FABRIC_CA_CLIENT_HOME=${PWD}/organizations/peerOrganizations/org1.example.com; export CORE_PEER_LOCALMSPID=Org1MSP; export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt; export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/groot@org1.example.com/msp; export CORE_PEER_ADDRESS=localhost:7051;

# Example certificate creation
export CERT_PROPERTIES=$(echo -n "{ \"objectType\": \"certificate\",\"certificateId\": \"1\", \"parentCertificateId\": \"1\", \"numChanged\": \"1\", \"nameSurname\": \"Alice Smith\", \"certType\": \"IT\", \"certDescription\": \"IT certificate\", \"validFrom\": \"2024-01-01\", \"validUntil\": \"2025-01-01\", \"UID\": \"990101/1234\", \"owner\": \"-----BEGIN CERTIFICATE-----\\nMIICpjCCAk2gAwIBAgIUTesCsh3utg0amUu6ag6HqFAzV5owCgYIKoZIzj0EAwIw\\ncDELMAkGA1UEBhMCVVMxFzAVBgNVBAgTDk5vcnRoIENhcm9saW5hMQ8wDQYDVQQH\\nEwZEdXJoYW0xGTAXBgNVBAoTEG9yZzEuZXhhbXBsZS5jb20xHDAaBgNVBAMTE2Nh\\nLm9yZzEuZXhhbXBsZS5jb20wHhcNMjQxMTIzMTIxNTAwWhcNMjUxMTIzMTIyNTAw\\nWjBdMQswCQYDVQQGEwJVUzEXMBUGA1UECBMOTm9ydGggQ2Fyb2xpbmExFDASBgNV\\nBAoTC0h5cGVybGVkZ2VyMQ8wDQYDVQQLEwZjbGllbnQxDjAMBgNVBAMTBWFsaWNl\\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkfFsDKL1a17HB5G4wNnpvfS7SNPQ\\nko/Tqt9iKcosJWNPk5rpV2XvMY7BiswO24DnqUc7BfzbZb5axmgoNFORoKOB1zCB\\n1DAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUvjoN7qqh\\niXk2/vJU3vamLolimrswHwYDVR0jBBgwFoAUw7cvR+OH4skKACi+dph+5DbAtsow\\nGgYDVR0RBBMwEYIPREVTS1RPUC1OVUZOOTQyMFgGCCoDBAUGBwgBBEx7ImF0dHJz\\nIjp7ImhmLkFmZmlsaWF0aW9uIjoiIiwiaGYuRW5yb2xsbWVudElEIjoiYWxpY2Ui\\nLCJoZi5UeXBlIjoiY2xpZW50In19MAoGCCqGSM49BAMCA0cAMEQCIGbBVMYo/seg\\nvWO4YEbe3GnoyzMZ5nPngScmkHuetzJwAiBgB79odNpJbI+WPi7UgIk1ynrcP+Jr\\nfxEFH+xXpgAbdg==\\n-----END CERTIFICATE-----\"}" | base64 | tr -d \\n)
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n private -c '{"function":"CreateCertificate","Args":[]}' --transient "{\"certificate_properties\":\"$CERT_PROPERTIES\"}"

sleep 2

# Certificate query as Org1
peer chaincode query -C mychannel -n private -c '{"function":"ReadNewestCertificateByParentId","Args":["1"]}'
sleep 2

# Query private data as Org1
peer chaincode query -C mychannel -n private -c '{"function":"ReadCertificatePrivateDetails","Args":["Org1MSPPrivateCollection","1"]}'
sleep 2

# Org2
export FABRIC_CA_CLIENT_HOME=${PWD}/organizations/peerOrganizations/org2.example.com/; fabric-ca-client register --caname ca-org2 --id.name bob --id.secret bobpw --id.type client --id.attrs "role=client:ecert,org=org2:ecert" --tls.certfiles "${PWD}/organizations/fabric-ca/org2/tls-cert.pem"; fabric-ca-client enroll -u https://bob:bobpw@localhost:8054 --caname ca-org2 -M "${PWD}/organizations/peerOrganizations/org2.example.com/users/bob@org2.example.com/msp" --tls.certfiles "${PWD}/organizations/fabric-ca/org2/tls-cert.pem"; cp "${PWD}/organizations/peerOrganizations/org2.example.com/msp/config.yaml" "${PWD}/organizations/peerOrganizations/org2.example.com/users/bob@org2.example.com/msp/config.yaml";

export FABRIC_CA_CLIENT_HOME=${PWD}/organizations/peerOrganizations/org2.example.com/; export CORE_PEER_LOCALMSPID=Org2MSP; export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt; export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org2.example.com/users/bob@org2.example.com/msp; export CORE_PEER_ADDRESS=localhost:9051;


# Certificate query as Org2
peer chaincode query -C mychannel -n private -c '{"function":"ReadNewestCertificateByParentId","Args":["1"]}'
sleep 2
# Checking if private data exist in Org2
peer chaincode query -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n private -c '{"function":"ReadCertificatePrivateDetails","Args":["Org2MSPPrivateCollection","1"]}'
sleep 2
# Query private data as Org2
peer chaincode query -C mychannel -n private -c '{"function":"ReadCertificatePrivateDetails","Args":["Org1MSPPrivateCollection","1"]}'
sleep 2

# Org1
export FABRIC_CA_CLIENT_HOME=${PWD}/organizations/peerOrganizations/org1.example.com; export CORE_PEER_LOCALMSPID=Org1MSP; export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt; export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/groot@org1.example.com/msp; export CORE_PEER_ADDRESS=localhost:7051;

# Changing certificate validity
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n private -c '{"function":"ChangeCertificateValidity","Args":["1", "2025-01-01", "2026-01-01"]}'
sleep 2
peer chaincode query -C mychannel -n private -c '{"function":"ReadNewestCertificateByParentId","Args":["1"]}'
sleep 2

# Revoking certificate
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem" -C mychannel -n private -c '{"function":"RevokeCertificate","Args":["1"]}' --peerAddresses localhost:7051 --tlsRootCertFiles "${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
sleep 2

# Certificate query as Org1
peer chaincode query -C mychannel -n private -c '{"function":"ReadNewestCertificateByParentId","Args":["1"]}'
sleep 2
# Query private data as Org1
peer chaincode query -C mychannel -n private -c '{"function":"ReadCertificatePrivateDetails","Args":["Org1MSPPrivateCollection","1"]}'
sleep 2

# Reading whole certificate history
peer chaincode query -C mychannel -n private -c '{"function":"GetCertificatesByPartialCompositeKey","Args":["1"]}'
sleep 2
