package checks

import (
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	absauth "github.com/microsoft/kiota-abstractions-go/authentication"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
)

// TestCredential, TestARMOptions and TestGraphHTTPClient replace the
// credential, the Resource Manager client options and the Microsoft Graph HTTP
// client for every client the scanner creates. All three are nil in
// production. The denial test sets them so every Azure and Graph request is
// refused in-process, which is the only way to see what each check reports
// when it cannot read the subscription.
var (
	TestCredential      azcore.TokenCredential
	TestARMOptions      *arm.ClientOptions
	TestGraphHTTPClient *http.Client
)

// Credential is the credential every client is built with.
func Credential() (azcore.TokenCredential, error) {
	if TestCredential != nil {
		return TestCredential, nil
	}
	return azidentity.NewDefaultAzureCredential(nil)
}

// ARMOptions is the client options value every Resource Manager client is
// built with; nil, the SDK default, outside the test.
func ARMOptions() *arm.ClientOptions {
	return TestARMOptions
}

// NewGraphClient builds the Microsoft Graph client.
func NewGraphClient(cred azcore.TokenCredential, scopes []string) (*msgraphsdk.GraphServiceClient, error) {
	if TestGraphHTTPClient != nil {
		adapter, err := msgraphsdk.NewGraphRequestAdapterWithParseNodeFactoryAndSerializationWriterFactoryAndHttpClient(
			&absauth.AnonymousAuthenticationProvider{}, nil, nil, TestGraphHTTPClient)
		if err != nil {
			return nil, err
		}
		return msgraphsdk.NewGraphServiceClient(adapter), nil
	}
	return msgraphsdk.NewGraphServiceClientWithCredentials(cred, scopes)
}
