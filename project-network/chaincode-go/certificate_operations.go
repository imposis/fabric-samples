package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
)

const certificateCollection string = "certificateCollection"

// Should be implemented, need to check
// TODO: Add certificate Issuer
//TODO: When certificate is revoked, create a new certificate with the old one as parent
//TODO: When certificate validity is extended, create a new certificate
//TODO: Owner should be the certificate holder
//TODO: Owner member of issuing org
//TODO: Endorsment policy only admins of organization

// Not implemented need to change and check
//TODO: Endorsment policy higher than 90% of members

// SmartContract
type SmartContract struct {
	contractapi.Contract
}

type Certificate struct {
	Type            string `json:"objectType"`
	CertificateId   string `json:"certificateId"`
	Version         string `json:"version"`
	NameSurname     string `json:"nameSurname"`
	CertType        string `json:"certType"`
	CertDescription string `json:"certDescription"`
	ValidFrom       string `json:"validFrom"`
	ValidUntil      string `json:"validUntil"`
	Owner           string `json:"owner"`
	Issuer          string `json:"issuer"`
}

type CertificatePrivateDetails struct {
	CertificateId string `json:"certificateId"`
	UID           string `json:"UID"`
}

func (s *SmartContract) CreateCertificate(ctx contractapi.TransactionContextInterface) error {
	// Get new certificate from transient map
	transientMap, err := ctx.GetStub().GetTransient()
	if err != nil {
		return fmt.Errorf("error getting transient: %v", err)
	}

	// certificate properties are private, therefore they get passed in transient field, instead of func args
	transientCertificateJSON, ok := transientMap["certificate_properties"]
	if !ok {
		// log error to stdout
		return fmt.Errorf("certificate not found in the transient map input")
	}

	type certificateTransientInput struct {
		CertificateId   string `json:"certificateId"`   //ID of the certificate for futher operations on certificate
		UID             string `json:"UID"`             //Unique ID of the certificate holder, only the owner organization can see this
		NameSurname     string `json:"nameSurname"`     //Name and surname of the certificate holder
		CertType        string `json:"certType"`        //Type of the certificate - IT, Economic, ...
		CertDescription string `json:"certDescription"` //Short description of the certificate
		ValidFrom       string `json:"validFrom"`       // Valid from date
		ValidUntil      string `json:"validUntil"`      //Valid until date
		Version         string `json:"version"`         //Holdes the information on the number of times the certificate has been changed
		Owner           string `json:"owner"`           //Owner is the certificate holder
	}

	var certificateInput certificateTransientInput
	err = json.Unmarshal(transientCertificateJSON, &certificateInput)
	if err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	if len(certificateInput.CertificateId) == 0 {
		return fmt.Errorf("ID field must be a non-empty string")
	}
	if len(certificateInput.UID) == 0 {
		return fmt.Errorf("UID field must be a non-empty string")
	}
	if len(certificateInput.NameSurname) == 0 {
		return fmt.Errorf("nameSurname field must be a non-empty string")
	}
	if len(certificateInput.CertType) == 0 {
		return fmt.Errorf("certType field must be a non-empty string")
	}
	if len(certificateInput.CertDescription) == 0 {
		return fmt.Errorf("certDescription field must be a non-empty string")
	}
	if len(certificateInput.ValidFrom) == 0 {
		return fmt.Errorf("validFrom field must be a non-empty string")
	}
	if len(certificateInput.ValidUntil) == 0 {
		return fmt.Errorf("validUntil field must be a non-empty string")
	}
	if len(certificateInput.Version) == 0 {
		return fmt.Errorf("version field must be a non-empty string")
	}

	validFrom, err := time.Parse("2006-01-02", certificateInput.ValidFrom)
	if err != nil {
		return fmt.Errorf("failed to parse validFrom: %v", err)
	}
	validUntil, err := time.Parse("2006-01-02", certificateInput.ValidUntil)
	if err != nil {
		return fmt.Errorf("failed to parse validUntil: %v", err)
	}
	if validFrom.After(validUntil) {
		return fmt.Errorf("validFrom must be before validUntil")
	}

	compositeKey, err := ctx.GetStub().CreateCompositeKey("certificate", []string{certificateInput.CertificateId, "0"})

	// Check if certificate already exists
	certificateAsBytes, err := ctx.GetStub().GetPrivateData(certificateCollection, compositeKey)
	if err != nil {
		return fmt.Errorf("failed to get certificate: %v", err)
	} else if certificateAsBytes != nil {
		fmt.Println("Certificate already exists: " + certificateInput.CertificateId)
		return fmt.Errorf("this certificate already exists: " + certificateInput.CertificateId)
	}

	// Get ID of submitting client identity
	clientID, err := submittingClientIdentity(ctx)
	if err != nil {
		return err
	}

	// Verify that the client is submitting request to peer in their organization
	// This is to ensure that a client from another org doesn't attempt to read or
	// write private data from this peer.
	err = verifyClientOrgMatchesPeerOrg(ctx)
	if err != nil {
		return fmt.Errorf("CreateCertificate cannot be performed: Error %v", err)
	}

	// Make submitting client the owner
	certificate := Certificate{
		Type:            "certificate",
		CertificateId:   certificateInput.CertificateId,
		NameSurname:     certificateInput.NameSurname,
		CertType:        certificateInput.CertType,
		CertDescription: certificateInput.CertDescription,
		ValidFrom:       certificateInput.ValidFrom,
		ValidUntil:      certificateInput.ValidUntil,
		Owner:           certificateInput.Owner,
		Version:         "0",
		Issuer:          clientID,
	}
	certificateJSONasBytes, err := json.Marshal(certificate)
	if err != nil {
		return fmt.Errorf("failed to marshal certificate into JSON: %v", err)
	}

	// Save certificate to private data collection
	// Typical logger, logs to stdout/file in the fabric managed docker container, running this chaincode
	// Look for container name like dev-peer0.org1.example.com-{chaincodename_version}-xyz
	log.Printf("CreateCertificate Put: collection %v, ID %v, owner %v", certificateCollection, compositeKey, clientID)

	err = ctx.GetStub().PutPrivateData(certificateCollection, compositeKey, certificateJSONasBytes)
	if err != nil {
		return fmt.Errorf("failed to put certificate into private data collecton: %v", err)
	}

	// Save certificate details to collection visible to owning organization
	certificatePrivateDetails := CertificatePrivateDetails{
		CertificateId: certificateInput.CertificateId,
		UID:           certificateInput.UID,
	}

	certificatePrivateDetailsAsBytes, err := json.Marshal(certificatePrivateDetails) // marshal certificate details to JSON
	if err != nil {
		return fmt.Errorf("failed to marshal into JSON: %v", err)
	}

	// Get collection name for this organization.
	orgCollection, err := getCollectionName(ctx)
	if err != nil {
		return fmt.Errorf("failed to infer private collection name for the org: %v", err)
	}

	// Put certificate appraised value into owners org specific private data collection
	log.Printf("Put: collection %v, ID %v", orgCollection, certificateInput.CertificateId)
	err = ctx.GetStub().PutPrivateData(orgCollection, compositeKey, certificatePrivateDetailsAsBytes)
	if err != nil {
		return fmt.Errorf("failed to put certificate private details: %v", err)
	}

	return nil
}

func (s *SmartContract) ChangeCertificateValidity(ctx contractapi.TransactionContextInterface, id string, validFrom string, validUntil string) error {
	log.Printf("ChangeCertificateValidUntil: collection %v, ID %v", certificateCollection, id)
	if len(id) == 0 {
		return fmt.Errorf("certificate ID must be a non-empty string")
	}

	certificate, err := s.ReadCertificate(ctx, id)
	if err != nil {
		return err
	}
	if certificate == nil {
		return fmt.Errorf("certificate %v does not exist", id)
	}

	validUntilDate, err := time.Parse("2006-01-02", validUntil)
	if err != nil {
		return fmt.Errorf("failed to parse validUntil input argument: %v", err)
	}

	validFromDate, err := time.Parse("2006-01-02", validFrom)
	if err != nil {
		return fmt.Errorf("failed to parse certificateValidFromDate: %v", err)
	}

	if validUntilDate.Before(validFromDate) {
		return fmt.Errorf("New validUntil date must be after validFrom date. %v < %v", validUntilDate, validFromDate)
	}

	newVersion, err := strconv.Atoi(certificate.Version)
	if err != nil {
		return fmt.Errorf("failed to parse certificate version: %v", err)
	}
	certificate.Version = strconv.Itoa(newVersion + 1)
	certificate.Type = "CertificateValidityChange"
	certificate.ValidUntil = validUntil
	certificate.ValidFrom = validFrom

	compositeKey, err := ctx.GetStub().CreateCompositeKey("certificate", []string{id, certificate.Version})
	if err != nil {
		return fmt.Errorf("failed to create composite key: %v", err)
	}

	certificateJSONasBytes, err := json.Marshal(certificate)
	if err != nil {
		return fmt.Errorf("failed to marshal certificate into JSON: %v", err)
	}

	err = ctx.GetStub().PutPrivateData(certificateCollection, compositeKey, certificateJSONasBytes)
	if err != nil {
		return fmt.Errorf("failed to put certificate into private data collecton: %v", err)
	}

	return nil
}

func (s *SmartContract) ReadAllCertificateVersions(ctx contractapi.TransactionContextInterface, id string) ([]*Certificate, error) {
	if len(id) == 0 {
		return nil, fmt.Errorf("certificate ID must be a non-empty string")
	}

	iterator, err := ctx.GetStub().GetPrivateDataByPartialCompositeKey(certificateCollection, "certificate", []string{id})
	if err != nil {
		return nil, fmt.Errorf("failed to read from private data collection: %v", err)
	}
	defer iterator.Close()

	var certificates []*Certificate

	for iterator.HasNext() {
		response, err := iterator.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to read from private data collection: %v", err)
		}

		var certificate *Certificate
		err = json.Unmarshal(response.Value, &certificate)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
		}

		certificates = append(certificates, certificate)
	}

	return certificates, nil
}

func (s *SmartContract) ReadCertificatePrivateDetails(ctx contractapi.TransactionContextInterface, collection string, id string) (*CertificatePrivateDetails, error) {
	log.Printf("ReadCertificatePrivateDetails: collection %v, ID %v", collection, id)
	if len(id) == 0 {
		return nil, fmt.Errorf("certificate ID must be a non-empty string")
	}

	iterator, err := ctx.GetStub().GetPrivateDataByPartialCompositeKey(collection, "certificate", []string{id})
	if err != nil {
		return nil, fmt.Errorf("failed to read from private data collection: %v", err)
	}
	defer iterator.Close()

	if !iterator.HasNext() {
		log.Printf("CertificatePrivateDetails for %v does not exist in collection %v", id, collection)
		return nil, nil
	}

	response, err := iterator.Next()
	if err != nil {
		return nil, fmt.Errorf("failed to read from private data collection: %v", err)
	}

	var certificateDetails *CertificatePrivateDetails
	err = json.Unmarshal(response.Value, &certificateDetails)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	return certificateDetails, nil
}

func (s *SmartContract) ReadCertificate(ctx contractapi.TransactionContextInterface, id string) (*Certificate, error) {
	certificates, err := s.ReadAllCertificateVersions(ctx, id)
	if err != nil {
		return nil, err
	}
	if len(certificates) == 0 {
		return nil, fmt.Errorf("certificate %v does not exist", id)
	}

	return newestCertificate(certificates), nil
}

func (s *SmartContract) RevokeCertificate(ctx contractapi.TransactionContextInterface, id string) error {
	if len(id) == 0 {
		return fmt.Errorf("certificate ID must be a non-empty string")
	}

	err := verifyClientOrgMatchesPeerOrg(ctx)
	if err != nil {
		return fmt.Errorf("RemoveCertificate cannot be performed: Error %v", err)
	}

	certificate, err := s.ReadCertificate(ctx, id)

	ownerCollection, err := getCollectionName(ctx)
	if err != nil {
		return fmt.Errorf("failed to get collection name: %v", err)
	}

	certificate.Type = "RevokedCertificate"
	newVersion, err := strconv.Atoi(certificate.Version)
	if err != nil {
		return fmt.Errorf("failed to parse certificate version: %v", err)
	}
	certificate.Version = strconv.Itoa(newVersion + 1)

	certificateJSONasBytes, err := json.Marshal(certificate)
	if err != nil {
		return fmt.Errorf("failed to marshal certificate into JSON: %v", err)
	}

	certificateId, err := ctx.GetStub().CreateCompositeKey("certificate", []string{certificate.CertificateId, certificate.Version})
	if err != nil {
		return fmt.Errorf("failed to create composite key: %v", err)
	}
	err = ctx.GetStub().PutPrivateData(ownerCollection, certificateId, certificateJSONasBytes)
	if err != nil {
		return fmt.Errorf("failed to put certificate into private data collecton: %v", err)
	}

	return nil
}

// getCollectionName is an internal helper function to get collection of submitting client identity.
func getCollectionName(ctx contractapi.TransactionContextInterface) (string, error) {

	// Get the MSP ID of submitting client identity
	clientMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", fmt.Errorf("failed to get verified MSPID: %v", err)
	}

	// Create the collection name
	orgCollection := clientMSPID + "PrivateCollection"

	return orgCollection, nil
}

// verifyClientOrgMatchesPeerOrg is an internal function used verify client org id and matches peer org id.
func verifyClientOrgMatchesPeerOrg(ctx contractapi.TransactionContextInterface) error {
	clientMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed getting the client's MSPID: %v", err)
	}
	peerMSPID, err := shim.GetMSPID()
	if err != nil {
		return fmt.Errorf("failed getting the peer's MSPID: %v", err)
	}

	if clientMSPID != peerMSPID {
		return fmt.Errorf("client from org %v is not authorized to read or write private data from an org %v peer", clientMSPID, peerMSPID)
	}

	return nil
}

func submittingClientIdentity(ctx contractapi.TransactionContextInterface) (string, error) {
	b64ID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return "", fmt.Errorf("Failed to read clientID: %v", err)
	}
	decodeID, err := base64.StdEncoding.DecodeString(b64ID)
	if err != nil {
		return "", fmt.Errorf("failed to base64 decode clientID: %v", err)
	}
	return string(decodeID), nil
}

func newestCertificate(certificates []*Certificate) *Certificate {
	var newest *Certificate
	for _, certificate := range certificates {
		if newest == nil || certificate.Version > newest.Version {
			newest = certificate
		}
	}
	return newest
}
