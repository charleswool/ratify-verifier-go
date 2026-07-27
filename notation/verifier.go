/*
Copyright The Ratify Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package notation

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/plugin"
	notationRegistry "github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation-go/verifier"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
	"github.com/notaryproject/ratify-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const notationVerifierType = "notation"

// VerifierOptions contains the options for creating a new Notation verifier.
type VerifierOptions struct {
	// Name is the instance name of the verifier to be created. Required.
	Name string

	// TrustPolicyDoc is a trustpolicy.json document. It should follow the spec:
	// https://github.com/notaryproject/notation-go/blob/v1.3.0/verifier/trustpolicy/oci.go#L29
	// Required.
	TrustPolicyDoc *trustpolicy.Document

	// TrustStore manages the certificates in the trust store. It should
	// implement the truststore.X509TrustStore interface:
	// https://github.com/notaryproject/notation-go/blob/v1.3.0/verifier/truststore/truststore.go#L52
	// Required.
	TrustStore truststore.X509TrustStore

	// PluginManager manages the plugins installed for Notation verifier. It
	// should implement the plugin.Manager interface:
	// https://github.com/notaryproject/notation-go/blob/v1.3.0/plugin/manager.go#L33
	// Optional.
	PluginManager plugin.Manager

	// CRL configures certificate revocation list checks. Optional. When set,
	// code signing and timestamping revocation validators are created using the
	// configured CRL fetcher.
	CRL *CRLOptions
}

// Verifier is a ratify.Verifier implementation that verifies Notation
// signatures.
type Verifier struct {
	name     string
	verifier notation.Verifier
}

// NewVerifier creates a new Notation verifier.
func NewVerifier(opts *VerifierOptions) (*Verifier, error) {
	if opts == nil {
		return nil, fmt.Errorf("verifier options cannot be nil")
	}
	if opts.Name == "" {
		return nil, fmt.Errorf("verifier name cannot be empty")
	}
	// TrustStore is an interface, so notation-go's untyped-nil check misses a
	// typed-nil value, which would panic during verification; guard it here.
	if isNil(opts.TrustStore) {
		return nil, fmt.Errorf("trust store cannot be nil")
	}

	notationVerifier, err := opts.toNotationVerifier()
	if err != nil {
		return nil, err
	}

	return &Verifier{
		name:     opts.Name,
		verifier: notationVerifier,
	}, nil
}

// toNotationVerifier builds the underlying notation.Verifier from opts, wiring
// CRL revocation validators when CRL checking is configured.
func (opts *VerifierOptions) toNotationVerifier() (notation.Verifier, error) {
	notationVerifierOpts := verifier.VerifierOptions{}
	if opts.CRL != nil {
		codeSigningValidator, timestampingValidator, err := newCRLHandler().revocationValidators(opts.CRL)
		if err != nil {
			return nil, err
		}
		notationVerifierOpts.RevocationCodeSigningValidator = codeSigningValidator
		notationVerifierOpts.RevocationTimestampingValidator = timestampingValidator
	}

	v, err := verifier.NewWithOptions(opts.TrustPolicyDoc, opts.TrustStore, opts.PluginManager, notationVerifierOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create notation verifier: %w", err)
	}
	return v, nil
}

// Name returns the name of the verifier.
func (v *Verifier) Name() string {
	return v.name
}

// Type returns the type of the verifier which is always `notation`.
func (v *Verifier) Type() string {
	return notationVerifierType
}

// Verifiable returns true if the artifact is a Notation signature.
func (v *Verifier) Verifiable(artifact ocispec.Descriptor) bool {
	return artifact.ArtifactType == notationRegistry.ArtifactTypeNotation && artifact.MediaType == ocispec.MediaTypeImageManifest
}

// Verify verifies the Notation signature.
func (v *Verifier) Verify(ctx context.Context, opts *ratify.VerifyOptions) (*ratify.VerificationResult, error) {
	signatureDesc, err := v.getSignatureBlobDesc(ctx, opts.Store, opts.Repository, opts.ArtifactDescriptor)
	if err != nil {
		return nil, fmt.Errorf("failed to get signature blob descriptor: %w", err)
	}

	signatureBlob, err := opts.Store.FetchBlob(ctx, opts.Repository, signatureDesc)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch signature blob: %w", err)
	}

	result := &ratify.VerificationResult{
		Verifier: v,
	}
	verifyOpts := notation.VerifierVerifyOptions{
		SignatureMediaType: signatureDesc.MediaType,
		ArtifactReference:  opts.Repository + "@" + opts.SubjectDescriptor.Digest.String(),
	}
	outcome, err := v.verifier.Verify(ctx, opts.SubjectDescriptor, signatureBlob, verifyOpts)
	if err != nil {
		result.Err = err
		return result, nil
	}

	cert := outcome.EnvelopeContent.SignerInfo.CertificateChain[0]
	result.Detail = map[string]string{
		"Issuer": cert.Issuer.String(),
		"SN":     cert.Subject.String(),
	}
	result.Description = "Notation signature verification succeeded"
	return result, nil
}

func (v *Verifier) getSignatureBlobDesc(ctx context.Context, store ratify.Store, repo string, artifactDesc ocispec.Descriptor) (ocispec.Descriptor, error) {
	manifestBytes, err := store.FetchManifest(ctx, repo, artifactDesc)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("failed to fetch manifest for artifact: %w", err)
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("failed to unmarshal manifest: %w", err)
	}

	if len(manifest.Layers) != 1 {
		return ocispec.Descriptor{}, fmt.Errorf("notation signature manifest requries exactly one signature envelope blob, got %d", len(manifest.Layers))
	}

	return manifest.Layers[0], nil
}
