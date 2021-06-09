package ecr

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/aquasecurity/fanal/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"

	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/ecr/ecriface"
	"golang.org/x/xerrors"
)

const ecrURL = "amazonaws.com"

type ECR struct {
	Client ecriface.ECRAPI
}

func getSession(option types.DockerOption) (*session.Session, error) {
	if option.AwsRoleArn != "" && option.AwsRegion != "" {
		var creds types.AmazonECRCredentials
		creds.RoleARN = option.AwsRoleArn
		creds.ExternalID = option.AwsExternalId

		if creds.RoleARN != "" {
			values, err := AssumeRole(creds.RoleARN, creds.ExternalID)
			if err != nil {
				return nil, xerrors.Errorf("failed to get assume role to get values, error: %s", err)
			}
			// todo: refactor
			return session.NewSessionWithOptions(
				session.Options{
					Config: aws.Config{
						Region: aws.String(option.AwsRegion),
						Credentials: credentials.NewStaticCredentialsFromCreds(
							credentials.Value{
								AccessKeyID:     values.AccessKeyID,
								SecretAccessKey: values.SecretAccessKey,
								SessionToken:    values.SessionToken,
							},
						),
					},
				})
		}
	}
	// create custom credential information if option is valid
	if option.AwsSecretKey != "" && option.AwsAccessKey != "" && option.AwsRegion != "" {
		return session.NewSessionWithOptions(
			session.Options{
				Config: aws.Config{
					Region: aws.String(option.AwsRegion),
					Credentials: credentials.NewStaticCredentialsFromCreds(
						credentials.Value{
							AccessKeyID:     option.AwsAccessKey,
							SecretAccessKey: option.AwsSecretKey,
							SessionToken:    option.AwsSessionToken,
						},
					),
				},
			})
	}
	// use shared configuration normally
	return session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	})
}

func (e *ECR) CheckOptions(domain string, option types.DockerOption) error {
	if !strings.HasSuffix(domain, ecrURL) {
		return xerrors.Errorf("ECR : %w", types.InvalidURLPattern)
	}
	sess := session.Must(getSession(option))
	svc := ecr.New(sess)
	e.Client = svc
	return nil
}

func (e *ECR) GetCredential(ctx context.Context) (username, password string, err error) {
	input := &ecr.GetAuthorizationTokenInput{}
	result, err := e.Client.GetAuthorizationTokenWithContext(ctx, input)
	if err != nil {
		return "", "", xerrors.Errorf("failed to get authorization token: %w", err)
	}
	for _, data := range result.AuthorizationData {
		b, err := base64.StdEncoding.DecodeString(*data.AuthorizationToken)
		if err != nil {
			return "", "", xerrors.Errorf("base64 decode failed: %w", err)
		}
		// e.g. AWS:eyJwYXlsb2...
		split := strings.SplitN(string(b), ":", 2)
		if len(split) == 2 {
			return split[0], split[1], nil
		}
	}
	return "", "", nil
}

func AssumeRole(roleArn, externalID string) (values credentials.Value, err error) {
	// Start assume role, these credentials will be used to to make the STS Assume Role API.
	sess := session.Must(session.NewSession())

	// Create the credentials from AssumeRoleProvider to assume the role referenced by the ARN valid for 15mins
	awscreds := stscreds.NewCredentials(sess, roleArn, func(p *stscreds.AssumeRoleProvider) {
		// optional External ID
		if externalID != ""{
			p.ExternalID = aws.String(externalID)
		}
	})
	values, err = awscreds.Get()
	if err != nil {
		return values, xerrors.Errorf("failed to get credentials from AssumeRoleProvider, error: %s", err)
	}

	return values, nil
}
