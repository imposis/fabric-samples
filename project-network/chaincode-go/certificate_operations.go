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

//TODO: Handle admin only write
//TODO: Handle admin only chaincode approval
//TODO: Check compositeKey options that work...

const certificateCollection string = "certificateCollection"

const revokedType string = "revoked"
const validityChanged string = "validityChange"
const certificateType string = "certificate"

const certIndex string = "parentCertificateId~numChanged"

// SmartContract
type SmartContract struct {
	contractapi.Contract
}

type Certificate struct {
	Type                string `json:"objectType"`
	CertificateId       string `json:"certificateId"`
	ParentCertificateId string `json:"parentCertificateId"`
	NumChanged          string `json:"numChanged"`
	NameSurname         string `json:"nameSurname"`
	CertType            string `json:"certType"`
	CertDescription     string `json:"certDescription"`
	ValidFrom           string `json:"validFrom"`
	ValidUntil          string `json:"validUntil"`
	Owner               string `json:"owner"`
	Issuer              string `json:"issuer"`
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
		CertificateId   string `json:"certificateId"`   //ID of the certificate, unqiue, assigned by overhead system
		UID             string `json:"UID"`             //Unique ID of the certificate holder, only the owner organization can see this
		NameSurname     string `json:"nameSurname"`     //Name and surname of the certificate holder
		CertType        string `json:"certType"`        //Type of the certificate - IT, Economic, ...
		CertDescription string `json:"certDescription"` //Short description of the certificate
		ValidFrom       string `json:"validFrom"`       // Valid from date
		ValidUntil      string `json:"validUntil"`      //Valid until date
		Owner           string `json:"owner"`           //Owner of the certificate
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
	if len(certificateInput.Owner) == 0 {
		return fmt.Errorf("owner field must be a non-empty string")
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

	// Check if certificate already exists
	certificateAsBytes, err := ctx.GetStub().GetPrivateData(certificateCollection, certificateInput.CertificateId)
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
		Type:                certificateType,
		CertificateId:       certificateInput.CertificateId,
		NameSurname:         certificateInput.NameSurname,
		CertType:            certificateInput.CertType,
		CertDescription:     certificateInput.CertDescription,
		ValidFrom:           certificateInput.ValidFrom,
		ValidUntil:          certificateInput.ValidUntil,
		ParentCertificateId: "",
		NumChanged:          "0",
		Issuer:              clientID,
		Owner:               certificateInput.Owner,
	}
	certificateJSONasBytes, err := json.Marshal(certificate)
	if err != nil {
		return fmt.Errorf("failed to marshal certificate into JSON: %v", err)
	}

	// Save certificate to private data collection
	// Typical logger, logs to stdout/file in the fabric managed docker container, running this chaincode
	// Look for container name like dev-peer0.org1.example.com-{chaincodename_version}-xyz
	log.Printf("CreateCertificate Put: collection %v, ID %v, owner %v", certificateCollection, certificateInput.CertificateId, clientID)

	err = ctx.GetStub().PutPrivateData(certificateCollection, certificateInput.CertificateId, certificateJSONasBytes)
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
	err = ctx.GetStub().PutPrivateData(orgCollection, certificateInput.CertificateId, certificatePrivateDetailsAsBytes)
	if err != nil {
		return fmt.Errorf("failed to put certificate private details: %v", err)
	}

	return nil
}

func (s *SmartContract) ChangeCertificateValidUntil(ctx contractapi.TransactionContextInterface, parentCertificateId string, newCertificateId string, validFrom string, validUntil string) (*Certificate, error) {
	log.Printf("ChangeCertificateValidUntil: collection %v, ID %v", certificateCollection, parentCertificateId)

	certificate, err := s.ReadCertificate(ctx, parentCertificateId)
	if err != nil {
		return nil, err
	}
	if certificate == nil {
		return nil, fmt.Errorf("certificate %v does not exist", parentCertificateId)
	}

	err = verifyClientOrgMatchesPeerOrg(ctx)
	if err != nil {
		return nil, fmt.Errorf("RemoveCertificate cannot be performed: Error %v", err)
	}

	newCertificate, err := s.ReadCertificate(ctx, newCertificateId)
	if err != nil {
		return nil, err
	}
	if newCertificate != nil {
		return nil, fmt.Errorf("certificate %v already exists", newCertificateId)
	}

	if certificate.Type == revokedType {
		return nil, fmt.Errorf("certificate is revoked")
	}

	validUntilDate, err := time.Parse("2006-01-02", validUntil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse validUntil input argument: %v", err)
	}

	certificateValidFromDate, err := time.Parse("2006-01-02", validFrom)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificateValidFromDate: %v", err)
	}

	if validUntilDate.Before(certificateValidFromDate) {
		return nil, fmt.Errorf("New validUntil date must be after validFrom date. %v < %v", validUntilDate, certificateValidFromDate)
	}

	certificate.ValidUntil = validUntil
	certificate.ValidFrom = validFrom
	certificate.CertificateId = newCertificateId
	certificate.Type = validityChanged
	certificate.ParentCertificateId = parentCertificateId
	certificate.NumChanged = increaseNumChanged(certificate.NumChanged)

	certificateJSONasBytes, err := json.Marshal(certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificate into JSON: %v", err)
	}

	err = ctx.GetStub().PutPrivateData(certificateCollection, newCertificateId, certificateJSONasBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to put certificate into private data collecton: %v", err)
	}

	return certificate, nil
}

func (s *SmartContract) ReadCertificate(ctx contractapi.TransactionContextInterface, certificateId string) (*Certificate, error) {
	log.Printf("ReadCertificate: collection %v, ID %v", certificateCollection, certificateId)
	certificateJSON, err := ctx.GetStub().GetPrivateData(certificateCollection, certificateId)
	if err != nil {
		return nil, fmt.Errorf("failed to read from private data collection: %v", err)
	}

	if certificateJSON == nil {
		log.Printf("%v does not exist in collection %v", certificateId, certificateCollection)
		return nil, nil
	}

	var certificate *Certificate
	err = json.Unmarshal(certificateJSON, &certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	return certificate, nil
}

func (s *SmartContract) ReadCertificatePrivateDetails(ctx contractapi.TransactionContextInterface, collection string, certificateId string) (*CertificatePrivateDetails, error) {
	log.Printf("ReadCertificatePrivateDetails: collection %v, ID %v", collection, certificateId)
	certificateDetailsJSON, err := ctx.GetStub().GetPrivateData(collection, certificateId)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate details: %v", err)
	}
	if certificateDetailsJSON == nil {
		log.Printf("CertificatePrivateDetails for %v does not exist in collection %v", certificateId, collection)
		return nil, nil
	}

	var certificateDetails *CertificatePrivateDetails
	err = json.Unmarshal(certificateDetailsJSON, &certificateDetails)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	return certificateDetails, nil
}

func (s *SmartContract) RevokeCertificate(ctx contractapi.TransactionContextInterface, parentCertificateId string, newCertificateId string) (*Certificate, error) {
	if len(parentCertificateId) == 0 {
		return nil, fmt.Errorf("certificate ID must be a non-empty string")
	}
	if len(newCertificateId) == 0 {
		return nil, fmt.Errorf("certificate ID must be a non-empty string")
	}

	newCertificate, err := s.ReadCertificate(ctx, newCertificateId)
	if err != nil {
		return nil, err
	}
	if newCertificate != nil {
		return nil, fmt.Errorf("certificate %v already exists", newCertificateId)
	}

	err = verifyClientOrgMatchesPeerOrg(ctx)
	if err != nil {
		return nil, fmt.Errorf("RemoveCertificate cannot be performed: Error %v", err)
	}

	log.Printf("Revoking Certificate: %v", parentCertificateId)

	valAsBytes, err := ctx.GetStub().GetPrivateData(certificateCollection, parentCertificateId)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %v", err)
	}
	if valAsBytes == nil {
		return nil, fmt.Errorf("certificate %v not found", parentCertificateId)
	}

	var certificate *Certificate
	err = json.Unmarshal(valAsBytes, &certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
	}

	if certificate.Type == revokedType {
		return nil, fmt.Errorf("certificate %v is already revoked", parentCertificateId)
	}

	certificate.Type = revokedType
	certificate.ParentCertificateId = parentCertificateId
	certificate.CertificateId = newCertificateId
	certificate.NumChanged = increaseNumChanged(certificate.NumChanged)

	certificateJSONasBytes, err := json.Marshal(certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificate into JSON: %v", err)
	}

	err = ctx.GetStub().PutPrivateData(certificateCollection, newCertificateId, certificateJSONasBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to put certificate into private data collecton: %v", err)
	}

	return certificate, nil
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

func increaseNumChanged(numChanged string) string {
	numChangedInt, _ := strconv.Atoi(numChanged)
	numChangedInt++
	return strconv.Itoa(numChangedInt)
}
