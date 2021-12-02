// Code generated by smithy-go-codegen DO NOT EDIT.

package ec2

import (
	"context"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Enable an Organizations member account as the IPAM admin account. You cannot
// select the Organizations management account as the IPAM admin account. For more
// information, see Enable integration with Organizations in the Amazon VPC IPAM
// User Guide.
func (c *Client) EnableIpamOrganizationAdminAccount(ctx context.Context, params *EnableIpamOrganizationAdminAccountInput, optFns ...func(*Options)) (*EnableIpamOrganizationAdminAccountOutput, error) {
	if params == nil {
		params = &EnableIpamOrganizationAdminAccountInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "EnableIpamOrganizationAdminAccount", params, optFns, c.addOperationEnableIpamOrganizationAdminAccountMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*EnableIpamOrganizationAdminAccountOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type EnableIpamOrganizationAdminAccountInput struct {

	// The Organizations member account ID that you want to enable as the IPAM account.
	//
	// This member is required.
	DelegatedAdminAccountId *string

	// A check for whether you have the required permissions for the action without
	// actually making the request and provides an error response. If you have the
	// required permissions, the error response is DryRunOperation. Otherwise, it is
	// UnauthorizedOperation.
	DryRun *bool

	noSmithyDocumentSerde
}

type EnableIpamOrganizationAdminAccountOutput struct {

	// The result of enabling the IPAM account.
	Success *bool

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationEnableIpamOrganizationAdminAccountMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsEc2query_serializeOpEnableIpamOrganizationAdminAccount{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpEnableIpamOrganizationAdminAccount{}, middleware.After)
	if err != nil {
		return err
	}
	if err = addSetLoggerMiddleware(stack, options); err != nil {
		return err
	}
	if err = awsmiddleware.AddClientRequestIDMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddComputeContentLengthMiddleware(stack); err != nil {
		return err
	}
	if err = addResolveEndpointMiddleware(stack, options); err != nil {
		return err
	}
	if err = v4.AddComputePayloadSHA256Middleware(stack); err != nil {
		return err
	}
	if err = addRetryMiddlewares(stack, options); err != nil {
		return err
	}
	if err = addHTTPSignerV4Middleware(stack, options); err != nil {
		return err
	}
	if err = awsmiddleware.AddRawResponseToMetadata(stack); err != nil {
		return err
	}
	if err = awsmiddleware.AddRecordResponseTiming(stack); err != nil {
		return err
	}
	if err = addClientUserAgent(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddErrorCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = addOpEnableIpamOrganizationAdminAccountValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opEnableIpamOrganizationAdminAccount(options.Region), middleware.Before); err != nil {
		return err
	}
	if err = addRequestIDRetrieverMiddleware(stack); err != nil {
		return err
	}
	if err = addResponseErrorMiddleware(stack); err != nil {
		return err
	}
	if err = addRequestResponseLogging(stack, options); err != nil {
		return err
	}
	return nil
}

func newServiceMetadataMiddleware_opEnableIpamOrganizationAdminAccount(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "ec2",
		OperationName: "EnableIpamOrganizationAdminAccount",
	}
}
