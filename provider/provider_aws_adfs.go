package provider

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Versent/saml2aws/pkg/awsconfig"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/beevik/etree"
	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/versent/saml2aws"
	"sigs.k8s.io/aws-iam-authenticator/pkg/token"
)

type ProviderAwsAdfs struct {
	MetadataURL     string
	ClusterID       string
	ServiceProvider *saml2.SAMLServiceProvider
}

type AWSRole struct {
	Name      string `json:"name"`
	ARN       string `json:"arn"`
	Principal string `json:"principal"`
}

type AWSCreds struct {
	AccessKey     string    `json:"accesskey"`
	SecretKey     string    `json:"secretkey"`
	SessionToken  string    `json:"sessiontoken"`
	SecurityToken string    `json:"securitytoken"`
	Principal     string    `json:"principal"`
	Expires       time.Time `json:"expires"`
}

type SigningKeyStore struct {
	privateKey *rsa.PrivateKey
	cert       []byte
}

func (ks SigningKeyStore) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	return ks.privateKey, ks.cert, nil
}

func NewProviderAwsAdfs(metadataURL string, clusterID string) (*ProviderAwsAdfs, error) {

	// Check if login URL is valid
	if metadataURL == "" {
		return nil, fmt.Errorf("metadata URL must be set")
	}
	_, err := url.ParseRequestURI(metadataURL)
	if err != nil {
		return nil, fmt.Errorf("invalid metadata URL: %w", err)
	}

	// Download metadata
	res, err := http.Get(metadataURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch IDP metadata: %w", err)
	}
	rawMetadata, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read IDP metadata: %w", err)
	}

	// Unmarshal metadata XML
	metadata := &types.EntityDescriptor{}
	err = xml.Unmarshal(rawMetadata, metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshald XML metadata: %s", err)
	}

	// Parse IDP certs from XML
	certStore := dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{},
	}
	for _, kd := range metadata.IDPSSODescriptor.KeyDescriptors {
		for idx, xcert := range kd.KeyInfo.X509Data.X509Certificates {
			if xcert.Data == "" {
				panic(fmt.Errorf("metadata certificate(%d) must not be empty", idx))
			}
			certData, err := base64.StdEncoding.DecodeString(xcert.Data)
			if err != nil {
				return nil, fmt.Errorf("decoding IDP base64 cert data: %s", err)
			}

			idpCert, err := x509.ParseCertificate(certData)
			if err != nil {
				return nil, fmt.Errorf("parsing IDP cert: %s", err)
			}

			certStore.Roots = append(certStore.Roots, idpCert)
		}
	}

	// Generate rsa private key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating keystore private key: %s", err)
	}

	// Create certificate
	now := time.Now()

	template := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "urn:amazon:webservices",
		},
		SerialNumber: big.NewInt(0),
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(365 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("creating keystore certificate: %s", err)
	}

	ks := SigningKeyStore{privateKey: key, cert: cert}

	// Create new SAML service provider
	sp := saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:         metadata.IDPSSODescriptor.SingleSignOnServices[0].Location,
		IdentityProviderSLOURL:         metadata.IDPSSODescriptor.SingleLogoutServices[0].Location,
		IdentityProviderIssuer:         metadata.EntityID,
		ServiceProviderIssuer:          "urn:amazon:webservices",
		AssertionConsumerServiceURL:    "https://127.0.0.1:8080/login?step=saml",
		ServiceProviderSLOURL:          "https://127.0.0.1:8080/login?step=saml",
		SignAuthnRequests:              false,
		SignAuthnRequestsCanonicalizer: dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(dsig.DefaultPrefix),
		SignAuthnRequestsAlgorithm:     "hhttp://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
		AudienceURI:                    "urn:amazon:webservices",
		IDPCertificateStore:            &certStore,
		SPKeyStore:                     ks,
		AllowMissingAttributes:         true,
	}

	sp.RequestedAuthnContext = &saml2.RequestedAuthnContext{
		Comparison: "minimum",
		Contexts:   []string{"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"},
	}

	return &ProviderAwsAdfs{
		MetadataURL:     metadataURL,
		ClusterID:       clusterID,
		ServiceProvider: &sp,
	}, nil
}

// Login is used to do SAML authentication to ADFS
func (p *ProviderAwsAdfs) Login() (string, error) {

	// Generate SAML auth URL
	var doc *etree.Document
	doc, err := p.ServiceProvider.BuildAuthRequestDocument()
	if err != nil {
		return "", fmt.Errorf("building auth request document: %w", err)
	}

	authURL, err := p.ServiceProvider.BuildAuthURLRedirect(p.ServiceProvider.AssertionConsumerServiceURL, doc)
	if err != nil {
		return "", fmt.Errorf("building auth redirect URL: %w", err)
	}

	return authURL, nil
}

// SAML is used to check SAML response and extract roles
func (p *ProviderAwsAdfs) SAML(samlResponse string) (string, map[string]string, error) {

	// Decode the SAML assertion and extract the roles
	decodedSamlAssertion, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return "", map[string]string{}, fmt.Errorf("error decoding saml assertion: %w", err)
	}
	extractedRoles, err := saml2aws.ExtractAwsRoles(decodedSamlAssertion)
	if err != nil {
		return "", map[string]string{}, fmt.Errorf("error extracting roles from saml assertion: %w", err)
	}
	parsedRoles, err := saml2aws.ParseAWSRoles(extractedRoles)
	if err != nil {
		return "", map[string]string{}, fmt.Errorf("error parsing roles from saml assertion: %w", err)
	}

	roles := map[string]string{}
	for _, role := range parsedRoles {

		// Extract account ID from role ARN
		// Example: arn:aws:iam::123456789012:role/role-name
		if len(strings.Split(role.RoleARN, ":")) != 6 {
			return "", map[string]string{}, fmt.Errorf("invalid role ARN: %s", role.RoleARN)
		}

		if len(strings.Split(role.RoleARN, "/")) != 2 {
			return "", map[string]string{}, fmt.Errorf("invalid role ARN: %s", role.RoleARN)
		}

		awsRole := AWSRole{
			Name:      fmt.Sprintf("%s:%s", strings.Split(role.RoleARN, ":")[4], strings.Split(role.RoleARN, "/")[1]),
			ARN:       role.RoleARN,
			Principal: role.PrincipalARN,
		}

		jsonRole, err := json.Marshal(awsRole)
		if err != nil {
			return "", map[string]string{}, fmt.Errorf("error marshalling role: %w", err)
		}

		b64Role := base64.StdEncoding.EncodeToString(jsonRole)
		if err != nil {
			return "", map[string]string{}, fmt.Errorf("error encoding role: %w", err)
		}

		roles[awsRole.Name] = b64Role
	}

	return samlResponse, roles, nil
}

// AssumeRole will take a SAML assertion and role and return AWS credentials
func (p *ProviderAwsAdfs) AssumeRole(SAMLAssertion, role string) (AWSCreds, error) {

	// Decode base64 role
	decodedRole, err := base64.StdEncoding.DecodeString(role)
	if err != nil {
		return AWSCreds{}, fmt.Errorf("error decoding role: %w", err)
	}

	// Unmarshal the role
	var awsRole AWSRole
	err = json.Unmarshal(decodedRole, &awsRole)
	if err != nil {
		return AWSCreds{}, fmt.Errorf("error unmarshalling role: %w", err)
	}

	// Create a new STS session
	sess, err := session.NewSession(&aws.Config{})
	if err != nil {
		return AWSCreds{}, fmt.Errorf("error creating aws session: %w", err)
	}
	svc := sts.New(sess)

	// Authenticate to the AWS STS using the SAML assertion and get temporary credentials
	assumeInput := &sts.AssumeRoleWithSAMLInput{
		PrincipalArn:    aws.String(awsRole.Principal),
		RoleArn:         aws.String(awsRole.ARN),
		SAMLAssertion:   aws.String(SAMLAssertion),
		DurationSeconds: aws.Int64(int64(36000)),
	}
	resp, err := svc.AssumeRoleWithSAML(assumeInput)
	if err != nil {
		return AWSCreds{}, fmt.Errorf("assuming role failed: %w", err)
	}

	creds := AWSCreds{
		AccessKey:     aws.StringValue(resp.Credentials.AccessKeyId),
		SecretKey:     aws.StringValue(resp.Credentials.SecretAccessKey),
		SessionToken:  aws.StringValue(resp.Credentials.SessionToken),
		SecurityToken: aws.StringValue(resp.Credentials.SessionToken),
		Principal:     aws.StringValue(resp.AssumedRoleUser.Arn),
		Expires:       resp.Credentials.Expiration.Local(),
	}

	return creds, nil
}

// Token returns a Kubernetes token based on temporary AWS credentials
func (p *ProviderAwsAdfs) Token(tmpCreds AWSCreds) (string, error) {

	// Set temporary credentials
	creds := &awsconfig.AWSCredentials{
		AWSAccessKey:     tmpCreds.AccessKey,
		AWSSecretKey:     tmpCreds.SecretKey,
		AWSSessionToken:  tmpCreds.SessionToken,
		AWSSecurityToken: tmpCreds.SecurityToken,
		PrincipalARN:     tmpCreds.Principal,
		Expires:          tmpCreds.Expires,
	}

	// Create a new AWS STS session with the temporary credentials
	sess, err := session.NewSession(&aws.Config{
		Credentials: credentials.NewStaticCredentials(creds.AWSAccessKey, creds.AWSSecretKey, creds.AWSSessionToken),
	})
	if err != nil {
		return "", fmt.Errorf("error creating session: %w", err)
	}
	svc := sts.New(sess)

	// Generate Kubernetes token with the STS session
	// it generates a token with a presigned URL to the STS session
	gen, err := token.NewGenerator(false, false)
	if err != nil {
		return "", fmt.Errorf("error creating token generator: %w", err)
	}
	tok, err := gen.GetWithSTS(p.ClusterID, svc)
	if err != nil {
		return "", fmt.Errorf("error getting token: %w", err)
	}

	return tok.Token, nil
}

// Valid checks if the token is still valid and if not returns an error
func (p *ProviderAwsAdfs) Valid(token string) error {

	// AWS STS Kubernetes token format: k8s-aws-v1.xxxxxxxxxxxxxxxxxxxxxxxxxxx
	// where xxxxxxxxx is a base64 encoded string containing a presigned URL
	// Get the presigned URL from the token
	urlPart := strings.Split(token, ".")
	if len(urlPart) != 2 {
		return fmt.Errorf("error splitting token")
	}

	// Decode the presigned URL encoded in base64
	decodedToken, err := base64.RawURLEncoding.DecodeString(urlPart[1])
	if err != nil {
		return fmt.Errorf("error decoding token: %s", err)
	}

	// Parse the presigned URL
	url, err := url.Parse(string(decodedToken))
	if err != nil {
		return fmt.Errorf("error parsing token url: %w", err)
	}

	// Get and parse the creation date from the presigned URL
	creationDate := url.Query().Get("X-Amz-Date")
	if creationDate == "" {
		return fmt.Errorf("error getting expiration from token url")
	}

	parsedCreationDate, err := time.Parse("20060102T150405Z", creationDate)
	if err != nil {
		return fmt.Errorf("error parsing creation date: %w", err)
	}

	// AWS for Kubernetes token expires after 15 minutes
	// we take a 1 minute margin
	expires := parsedCreationDate.Add(14 * time.Minute)

	// Check if token expired
	if time.Now().After(expires) {
		return fmt.Errorf("token expired at %s", expires)
	}

	return nil
}
