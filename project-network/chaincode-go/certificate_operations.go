package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
)

const revokedType string = "revoked"
const validityChanged string = "validityChange"
const certificateType string = "certificate"

const compositeKeyType = "certificate"

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
	IssuerOrg           string `json:"issuerOrg"`
}

type CertificatePrivateDetails struct {
	CertificateId string `json:"certificateId"`
	UID           string `json:"UID"`
}

func (s *SmartContract) CreateCertificate(ctx contractapi.TransactionContextInterface) error {
	if err := checkClientRole(ctx, "admin"); err != nil {
		return err
	}

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

	certificateCheck, _ := s.ReadNewestCertificateByParentId(ctx, certificateInput.CertificateId)
	if certificateCheck != nil {
		return fmt.Errorf("Certificate %v already exists", certificateInput.CertificateId)
	}

	// Get ID of submitting client identity
	clientID, err := submittingClientIdentity(ctx)
	if err != nil {
		return err
	}

	issuerOrg, found, err := ctx.GetClientIdentity().GetAttributeValue("org")
	if err != nil {
		return fmt.Errorf("failed to get client's org attribute: %v", err)
	}
	if !found {
		return fmt.Errorf("client does not have the org assigned: %s", issuerOrg)
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
		ParentCertificateId: certificateInput.CertificateId,
		NumChanged:          "0",
		Issuer:              clientID,
		IssuerOrg:           issuerOrg,
		Owner:               decodeCert(certificateInput.Owner),
	}
	certificateJSONasBytes, err := json.Marshal(certificate)
	if err != nil {
		return fmt.Errorf("failed to marshal certificate into JSON: %v", err)
	}

	// Save certificate to private data collection
	// Typical logger, logs to stdout/file in the fabric managed docker container, running this chaincode
	// Look for container name like dev-peer0.org1.example.com-{chaincodename_version}-xyz
	log.Printf("CreateCertificate Put: ID %v, owner %v", certificateInput.CertificateId, clientID)

	compositeKey, err := ctx.GetStub().CreateCompositeKey(compositeKeyType, []string{certificate.ParentCertificateId, certificate.CertificateId})

	err = ctx.GetStub().PutState(compositeKey, certificateJSONasBytes)
	if err != nil {
		return fmt.Errorf("failed to put certificate into private data collection: %v", err)
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

func (s *SmartContract) ChangeCertificateValidity(ctx contractapi.TransactionContextInterface, parentCertificateId string, validFrom string, validUntil string) (*Certificate, error) {
	log.Printf("ChangeCertificateValidity: ID %v", parentCertificateId)

	if err := checkClientRole(ctx, "admin"); err != nil {
		return nil, err
	}

	certificate, err := s.ReadNewestCertificateByParentId(ctx, parentCertificateId)
	if err != nil {
		return nil, err
	}
	if certificate == nil {
		return nil, fmt.Errorf("Parent certificate %v does not exist", parentCertificateId)
	}

	err = verifyClientOrgMatchesPeerOrg(ctx)
	if err != nil {
		return nil, fmt.Errorf("Change certificate validity cannot be performed: Error %v", err)
	}

	if err = checkClientOrg(ctx, certificate.IssuerOrg); err != nil {
		return nil, err
	}

	if certificate.Type == revokedType {
		return nil, fmt.Errorf("Parent certificate is revoked already")
	}

	validUntilDate, err := time.Parse("2006-01-02", validUntil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse validUntil input argument: %v", err)
	}

	validFromDate, err := time.Parse("2006-01-02", validFrom)
	if err != nil {
		return nil, fmt.Errorf("failed to parse validFromDate: %v", err)
	}

	if validUntilDate.Before(validFromDate) {
		return nil, fmt.Errorf("New validUntil date must be after validFrom date. %v < %v", validUntilDate, validFromDate)
	}

	certificate.ValidUntil = validUntil
	certificate.ValidFrom = validFrom
	certificate.CertificateId = ctx.GetStub().GetTxID()
	certificate.Type = validityChanged
	certificate.NumChanged = increaseNumChanged(certificate.NumChanged)

	certificateJSONasBytes, err := json.Marshal(certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificate into JSON: %v", err)
	}

	compositeKey, err := ctx.GetStub().CreateCompositeKey(compositeKeyType, []string{parentCertificateId, certificate.CertificateId})

	err = ctx.GetStub().PutState(compositeKey, certificateJSONasBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to put certificate into collection: %v", err)
	}

	return certificate, nil
}

func (s *SmartContract) ReadNewestCertificateByParentId(ctx contractapi.TransactionContextInterface, parentCertificateId string) (*Certificate, error) {
	log.Printf("ReadNewestCertificateByParentId: ID %v", parentCertificateId)
	certificates, err := s.GetCertificatesByPartialCompositeKey(ctx, parentCertificateId)

	if err != nil {
		return nil, err
	}
	if len(certificates) == 0 {
		return nil, fmt.Errorf("Certificate %v does not exist", parentCertificateId)
	}

	certificate := getNewestCertificateChange(certificates)

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

func (s *SmartContract) RevokeCertificate(ctx contractapi.TransactionContextInterface, parentCertificateId string) (*Certificate, error) {
	if err := checkClientRole(ctx, "admin"); err != nil {
		return nil, err
	}

	if len(parentCertificateId) == 0 {
		return nil, fmt.Errorf("certificate ID must be a non-empty string")
	}

	certificate, err := s.ReadNewestCertificateByParentId(ctx, parentCertificateId)
	if err != nil {
		return nil, err
	}
	if certificate == nil {
		return nil, fmt.Errorf("certificate %v does not exist", parentCertificateId)
	}

	if err = checkClientOrg(ctx, certificate.IssuerOrg); err != nil {
		return nil, err
	}

	err = verifyClientOrgMatchesPeerOrg(ctx)
	if err != nil {
		return nil, fmt.Errorf("RevokeCertificate cannot be performed: Error %v", err)
	}

	log.Printf("Revoking Certificate: %v", parentCertificateId)

	if certificate.Type == revokedType {
		return nil, fmt.Errorf("certificate %v is already revoked", parentCertificateId)
	}

	certificate.Type = revokedType
	certificate.CertificateId = ctx.GetStub().GetTxID()
	certificate.NumChanged = increaseNumChanged(certificate.NumChanged)

	certificateJSONasBytes, err := json.Marshal(certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificate into JSON: %v", err)
	}

	compositeKey, err := ctx.GetStub().CreateCompositeKey(compositeKeyType, []string{parentCertificateId, certificate.CertificateId})

	err = ctx.GetStub().PutState(compositeKey, certificateJSONasBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to put certificate into collection: %v", err)
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

func (s *SmartContract) GetCertificatesByPartialCompositeKey(ctx contractapi.TransactionContextInterface, partialCompositeKey string) ([]*Certificate, error) {
	resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey(compositeKeyType, []string{partialCompositeKey})
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var certificates []*Certificate
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var certificate Certificate
		err = json.Unmarshal(queryResponse.Value, &certificate)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, &certificate)
	}

	return certificates, nil
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

// Gets the MSP ID of submitting client identity
// Used for Issuer in Certificate
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

// increaseNumChanged is an internal helper function to increase numChanged of certificate
func increaseNumChanged(numChanged string) string {
	numChangedInt, _ := strconv.Atoi(numChanged)
	numChangedInt++
	return strconv.Itoa(numChangedInt)
}

// decodeCert is an internal helper function to decode certificate of owner for storing in certificate
// Hyperledger uses x509::subject::issuer certificate and format, expected to be passed a correctly formatted certificate string
// If not correctly formatted, returns the original string and stores it regardles
func decodeCert(certPEM string) string {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return certPEM
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return certPEM
	}

	// Print certificate details
	return fmt.Sprintf("x509::%s::%s", cert.Subject, cert.Issuer)
}

// getNewestCertificateChange is an internal helper function to get the newest certificate change
// returns the newest certificate
func getNewestCertificateChange(certificates []*Certificate) *Certificate {
	var newestCertificate *Certificate
	for _, certificate := range certificates {
		if newestCertificate == nil || certificate.NumChanged > newestCertificate.NumChanged {
			newestCertificate = certificate
		}
	}
	return newestCertificate
}

func checkClientRole(ctx contractapi.TransactionContextInterface, requiredRole string) error {
	role, found, err := ctx.GetClientIdentity().GetAttributeValue("role")
	if err != nil {
		return fmt.Errorf("failed to get client's role attribute: %v", err)
	}

	if !found || role != requiredRole {
		return fmt.Errorf("client does not have the required role: %s", requiredRole)
	}

	return nil
}

func checkClientOrg(ctx contractapi.TransactionContextInterface, requiredOrg string) error {
	org, found, err := ctx.GetClientIdentity().GetAttributeValue("org")
	if err != nil {
		return fmt.Errorf("failed to get client's org attribute: %v", err)
	}

	if !found || org != requiredOrg {
		return fmt.Errorf("client does not have the required org: %s", requiredOrg)
	}

	return nil
}
