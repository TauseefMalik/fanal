package types

// AmazonECRCredentials: AWS ECR
type AmazonECRCredentials struct {
	// AccountID: The AWS account ID.
	AccountID string

	// RoleARN: The ARN of the role to assume.
	RoleARN string

	// ExternalID: The external ID to authenticate with.
	ExternalID string
}