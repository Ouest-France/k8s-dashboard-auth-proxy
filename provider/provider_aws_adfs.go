package provider

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/versent/saml2aws"
	"github.com/versent/saml2aws/pkg/awsconfig"
	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/creds"
	"sigs.k8s.io/aws-iam-authenticator/pkg/token"
)

const SessionDuration = 3600

type ProviderAwsAdfs struct {
	LoginURL  string
	ClusterID string
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

func NewProviderAwsAdfs(loginURL string, clusterID string) (*ProviderAwsAdfs, error) {

	// Check if login URL is valid
	if loginURL == "" {
		return nil, fmt.Errorf("login URL must be set")
	}
	_, err := url.ParseRequestURI(loginURL)
	if err != nil {
		return nil, fmt.Errorf("invalid login URL: %w", err)
	}

	return &ProviderAwsAdfs{
		LoginURL:  loginURL,
		ClusterID: clusterID,
	}, nil
}

// Login is used to do SAML authentication to ADFS
// use the SAML assertion to assume an AWS role
// and return a Kubernetes token
func (p *ProviderAwsAdfs) Login(user, password string) (string, map[string]string, error) {

	// Create a new SAML idp account to use with saml2aws
	account := cfg.NewIDPAccount()
	account.URL = p.LoginURL
	account.Username = user
	account.Provider = "ADFS"
	account.MFA = "Auto"
	account.AmazonWebservicesURN = "urn:amazon:webservices"
	account.SessionDuration = SessionDuration

	// Create a new SAML client
	client, err := saml2aws.NewSAMLClient(account)
	if err != nil {
		return "", map[string]string{}, fmt.Errorf("error building saml client: %w", err)
	}

	// Create a new login details object
	login := &creds.LoginDetails{
		Username: account.Username,
		Password: password,
		URL:      p.LoginURL,
	}

	// Authenticate to the ADFS and get the SAML assertion with roles
	samlAssertion, err := client.Authenticate(login)
	if err != nil {
		return "", map[string]string{}, fmt.Errorf("error authenticating to IdP: %w", err)
	}

	// Decode the SAML assertion and extract the roles
	decodedSamlAssertion, err := base64.StdEncoding.DecodeString(samlAssertion)
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
		re := regexp.MustCompile(`^arn:aws:iam::(\d+):role\/([\w+=,.@-]{1,64})$`)
		match := re.FindSubmatch([]byte(role.RoleARN))

		if len(match) != 3 {
			return "", map[string]string{}, fmt.Errorf("invalid role ARN: %s", role.RoleARN)
		}

		awsRole := AWSRole{
			Name:      fmt.Sprintf("%s:%s", match[1], match[2]),
			ARN:       role.RoleARN,
			Principal: role.PrincipalARN,
		}

		jsonRole, err := json.Marshal(awsRole)
		if err != nil {
			return "", map[string]string{}, fmt.Errorf("error marshalling role: %w", err)
		}

		b64Role := base64.StdEncoding.EncodeToString(jsonRole)

		roles[awsRole.Name] = b64Role
	}

	return samlAssertion, roles, nil
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
		DurationSeconds: aws.Int64(SessionDuration),
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

	// Check if the temporary credentials are expired
	if tmpCreds.Expires.Before(time.Now()) {
		return "", fmt.Errorf("temporary credentials expired")
	}

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
