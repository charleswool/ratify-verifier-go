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

package cosign

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/notaryproject/ratify-go"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/signature"
)

const (
	verifierTypeCosign = "cosign"

	mediaTypeCosignArtifactSignature = "application/vnd.dev.cosign.artifact.sig.v1+json"
	mediaTypeSigstoreBundle01        = "application/vnd.dev.sigstore.bundle+json;version=0.1"
	mediaTypeSimpleSigning           = "application/vnd.dev.cosign.simplesigning.v1+json"

	annotationKeyBundle    = "dev.sigstore.cosign/bundle"
	annotationKeyCert      = "dev.sigstore.cosign/certificate"
	annotationKeySignature = "dev.cosignproject.cosign/signature"
)

// PublicKeyConfig contains the configuration for key-based verification.
type PublicKeyConfig struct {
	// PublicKey for key-based verification.
	PublicKey crypto.PublicKey

	// SignatureAlgorithm defines the algorithm used for signature verification.
	// Optional. If not provided, defaults to SHA256.
	SignatureAlgorithm crypto.Hash

	// ValidityPeriodStart defines the start time for the public key validity
	// period. Optional. If not provided, the key is considered valid from the
	// beginning of time.
	ValidityPeriodStart time.Time

	// ValidityPeriodEnd defines the end time for the public key validity period.
	// Optional. If not provided, the key is considered valid until the end of
	// time.
	ValidityPeriodEnd time.Time
}

// VerifierOptions contains the options for creating a new Cosign verifier.
type VerifierOptions struct {
	// Name is the instance name of the verifier to be created. Required.
	Name string

	// TrustedRoot defines the trusted root for verification. For keyless verification,
	// this will contain Fulcio certificates and Rekor public keys. Optional.
	// If not provided, the default Sigstore trusted root will be used.
	TrustedRoot *root.TrustedRoot

	// GetPublicKeys retrieves the public keys for key-based verification.
	GetPublicKeys func(ctx context.Context) ([]*PublicKeyConfig, error)

	// IdentityPolicies contains policies for keyless verification.
	// These policies specify which OIDC identities are trusted. Optional.
	IdentityPolicies []verify.PolicyOption

	// IgnoreTLog when set to true, skips Artifact transparency log verification.
	// Only applies to keyless verification. Optional, defaults to false.
	IgnoreTLog bool

	// IgnoreCTLog when set to true, skips certificate transparency log verification.
	// Only applies to keyless verification. Optional, defaults to false.
	IgnoreCTLog bool

	// TUFOptions provides custom TUF client options for fetching trusted root.
	// Optional.
	TUFOptions *tuf.Options
}

// Verifier is a ratify.Verifier implementation that verifies Cosign signatures.
type Verifier struct {
	name             string
	identityPolicies []verify.PolicyOption
	ignoreTLog       bool
	getPublicKeys    func(context.Context) ([]*PublicKeyConfig, error)
	getVerifier      func() (*verify.Verifier, error)
}

// NewVerifier creates a new Cosign verifier.
func NewVerifier(opts *VerifierOptions) (*Verifier, error) {
	if opts == nil {
		return nil, fmt.Errorf("verifier options are required")
	}
	if opts.Name == "" {
		return nil, fmt.Errorf("verifier name is required")
	}

	var getVerifier func() (*verify.Verifier, error)
	if opts.GetPublicKeys != nil {
		getVerifier = func() (*verify.Verifier, error) {
			return createVerifier(opts)
		}
	} else {
		v, err := createVerifier(opts)
		if err != nil {
			return nil, fmt.Errorf("failed to create verifier: %w", err)
		}
		getVerifier = func() (*verify.Verifier, error) {
			return v, nil
		}
	}

	return &Verifier{
		getVerifier:      getVerifier,
		name:             opts.Name,
		identityPolicies: opts.IdentityPolicies,
		ignoreTLog:       opts.IgnoreTLog,
		getPublicKeys:    opts.GetPublicKeys,
	}, nil
}

func createVerifier(opts *VerifierOptions) (*verify.Verifier, error) {
	var trustedMaterial root.TrustedMaterialCollection

	// Create trusted material from public keys if provided.
	trustedPublicKeyMaterial, err := createTrustedMaterialFromPublicKeys(context.Background(), opts.GetPublicKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to create trusted material from public keys: %w", err)
	}
	trustedMaterial = append(trustedMaterial, trustedPublicKeyMaterial...)

	// Keyless verification: use provided trusted root or fetch from TUF
	if opts.TrustedRoot != nil {
		trustedMaterial = append(trustedMaterial, opts.TrustedRoot)
	} else {
		// Fetch default Sigstore trusted root
		if opts.TUFOptions == nil {
			opts.TUFOptions = tuf.DefaultOptions()
		}
		tufClient, err := tuf.New(opts.TUFOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to create TUF client: %w", err)
		}

		trustedRoot, err := root.GetTrustedRoot(tufClient)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch trusted root: %w", err)
		}
		trustedMaterial = append(trustedMaterial, trustedRoot)
	}

	// Create verifier options for signature verification
	var verifierOpts []verify.VerifierOption

	// Configure transparency log verification
	if !opts.IgnoreTLog {
		verifierOpts = append(verifierOpts, verify.WithTransparencyLog(1))
	}

	// Configure timestamp verification
	verifierOpts = append(verifierOpts, verify.WithObserverTimestamps(1))

	// Configure certificate transparency log verification
	if !opts.IgnoreCTLog {
		verifierOpts = append(verifierOpts, verify.WithSignedCertificateTimestamps(1))
	}

	// Create the underlying cosign verifier
	return verify.NewVerifier(trustedMaterial, verifierOpts...)
}

func createTrustedMaterialFromPublicKeys(ctx context.Context, getPublicKeys func(context.Context) ([]*PublicKeyConfig, error)) ([]root.TrustedMaterial, error) {
	var trustedMaterial []root.TrustedMaterial
	if getPublicKeys == nil {
		return trustedMaterial, nil
	}

	publicKeys, err := getPublicKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get public keys: %w", err)
	}

	for _, config := range publicKeys {
		if config == nil {
			return nil, fmt.Errorf("public key config cannot be nil")
		}
		if config.SignatureAlgorithm == 0 {
			// Default to SHA256 if no algorithm is specified
			config.SignatureAlgorithm = crypto.SHA256
		}
		trustedMaterial = append(trustedMaterial, createTrustedPublicKeyMaterial(config))
	}
	return trustedMaterial, nil
}

// Name returns the name of the verifier.
func (v *Verifier) Name() string {
	return v.name
}

// Type returns the type of the verifier which is always `cosign`.
func (v *Verifier) Type() string {
	return verifierTypeCosign
}

// Verifiable returns true if the artifact is a Cosign signature.
func (v *Verifier) Verifiable(artifact ocispec.Descriptor) bool {
	return artifact.ArtifactType == mediaTypeCosignArtifactSignature &&
		artifact.MediaType == ocispec.MediaTypeImageManifest
}

// Verify verifies the artifact containing Cosign signatures.
// The verification passes if at least one valid signature is found.
func (v *Verifier) Verify(ctx context.Context, opts *ratify.VerifyOptions) (*ratify.VerificationResult, error) {
	sigManifestBytes, err := opts.Store.FetchManifest(ctx, opts.Repository, opts.ArtifactDescriptor)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch signature manifest: %w", err)
	}

	var sigManifest ocispec.Manifest
	if err := json.Unmarshal(sigManifestBytes, &sigManifest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal signature manifest: %w", err)
	}

	// Get signature descriptors of simple signing layers
	layers, err := getSignatureDescriptors(ctx, opts.Store, opts.Repository, opts.ArtifactDescriptor)
	if err != nil {
		return nil, fmt.Errorf("failed to get signature descriptors: %w", err)
	}

	validSigFound := false
	var reports []*layerReport

	for _, layer := range layers {
		report := &layerReport{
			Digest: layer.Digest.String(),
		}
		if res, err := v.verifySignatureLayer(layer); err != nil {
			report.Error = err
			report.Succeeded = false
		} else {
			validSigFound = true
			report.Succeeded = true
			report.VerificationResult = res
		}
		reports = append(reports, report)
	}

	result := &ratify.VerificationResult{
		Verifier: v,
		Detail: map[string][]*layerReport{
			"verifiedSignatures": reports,
		},
	}
	if validSigFound {
		result.Description = "Cosign signature verification succeeded"
	} else {
		result.Description = "Cosign signature verification failed: no valid signatures found"
		result.Err = errors.New("no valid signatures found, see result for details")
	}
	return result, nil
}

// verifySignatureLayer verifies a single simple signing layer.
func (v *Verifier) verifySignatureLayer(manifestLayer ocispec.Descriptor) (*verify.VerificationResult, error) {
	// Build the verification material for the bundle
	verificationMaterial, err := getBundleVerificationMaterial(manifestLayer, v.ignoreTLog, v.getPublicKeys)
	if err != nil {
		return nil, fmt.Errorf("error getting verification material: %v", err)
	}

	// Build the message signature for the bundle
	msgSignature, err := getBundleMsgSignature(manifestLayer)
	if err != nil {
		return nil, fmt.Errorf("error getting message signature: %v", err)
	}

	// Construct and verify the bundle
	pb := protobundle.Bundle{
		MediaType:            mediaTypeSigstoreBundle01,
		VerificationMaterial: verificationMaterial,
		Content:              msgSignature,
	}
	bun, err := bundle.NewBundle(&pb)
	if err != nil {
		return nil, fmt.Errorf("error creating bundle: %v", err)
	}

	return v.verifyBundle(bun, manifestLayer.Digest)
}

// verifyBundle verifies the bundle using the configured verifier.
func (v *Verifier) verifyBundle(bundleObj *bundle.Bundle, layer digest.Digest) (*verify.VerificationResult, error) {
	digestBytes, err := hex.DecodeString(layer.Encoded())
	if err != nil {
		return nil, fmt.Errorf("failed to decode digest hex: %w", err)
	}

	// Create artifact policy
	artifactPolicy := verify.WithArtifactDigest(string(layer.Algorithm()), digestBytes)
	verifier, err := v.getVerifier()
	if err != nil {
		return nil, fmt.Errorf("failed to get verifier: %w", err)
	}
	return verifier.Verify(bundleObj, verify.NewPolicy(artifactPolicy, v.identityPolicies...))
}

// getBundleVerificationMaterial returns the bundle verification material from
// the simple signing layer
func getBundleVerificationMaterial(manifestLayer ocispec.Descriptor, ignoreTlog bool, getPublicKeys func(ctx context.Context) ([]*PublicKeyConfig, error)) (*protobundle.VerificationMaterial, error) {
	// 1. Get the transparency log entries
	var tlogEntries []*protorekor.TransparencyLogEntry
	var err error
	if !ignoreTlog {
		tlogEntries, err = getVerificationMaterialTlogEntries(manifestLayer)
		if err != nil {
			return nil, fmt.Errorf("error getting tlog entries: %w", err)
		}
	}

	// 2. Construct the verification material based on the type of verification
	verificationMaterial := &protobundle.VerificationMaterial{
		TlogEntries:               tlogEntries,
		TimestampVerificationData: nil, // TODO: support RFC3161Timestamp.
	}
	// If getPublicKeys is nil, this indicates keyless verification.
	// If getPublicKeys is non-nil, this indicates key-based verification.
	if getPublicKeys != nil {
		// If we have public keys, construct an empty public key material
		verificationMaterial.Content = &protobundle.VerificationMaterial_PublicKey{
			PublicKey: &protocommon.PublicKeyIdentifier{
				Hint: "",
			},
		}
	} else {
		// Otherwise, get the signing certificate chain from the manifest
		signingCert, err := getVerificationMaterialX509CertificateChain(manifestLayer)
		if err != nil {
			return nil, fmt.Errorf("error getting signing certificate: %w", err)
		}
		verificationMaterial.Content = signingCert
	}

	return verificationMaterial, nil
}

// getVerificationMaterialX509CertificateChain returns the verification material
// X509 certificate chain from the simple signing layer
func getVerificationMaterialX509CertificateChain(manifestLayer ocispec.Descriptor) (*protobundle.VerificationMaterial_X509CertificateChain, error) {
	// 1. Get the PEM certificate from the simple signing layer
	pemCert := manifestLayer.Annotations[annotationKeyCert]
	// 2. Construct the DER encoded version of the PEM certificate
	block, _ := pem.Decode([]byte(pemCert))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	signingCert := protocommon.X509Certificate{
		RawBytes: block.Bytes,
	}
	// 3. Construct the X509 certificate chain
	return &protobundle.VerificationMaterial_X509CertificateChain{
		X509CertificateChain: &protocommon.X509CertificateChain{
			Certificates: []*protocommon.X509Certificate{&signingCert},
		},
	}, nil
}

// bundleAnnotation represents the structure of the bundle annotation
type bundleAnnotation struct {
	Payload              *bundlePayload `json:"Payload"`
	SignedEntryTimestamp *string        `json:"SignedEntryTimestamp"`
}

// bundlePayload represents the payload structure within the bundle
type bundlePayload struct {
	LogIndex       *float64 `json:"logIndex"`
	LogID          *string  `json:"logID"`
	IntegratedTime *float64 `json:"integratedTime"`
	Body           *string  `json:"body"`
}

// payloadBody represents the structure of the decoded body
type payloadBody struct {
	APIVersion *string `json:"apiVersion"`
	Kind       *string `json:"kind"`
}

func (b *bundleAnnotation) validate() error {
	if b.Payload == nil {
		return fmt.Errorf("bundle payload is missing")
	}
	if b.Payload.LogIndex == nil {
		return fmt.Errorf("bundle payload logIndex is missing")
	}
	if b.Payload.LogID == nil {
		return fmt.Errorf("bundle payload logID is missing")
	}
	if b.Payload.IntegratedTime == nil {
		return fmt.Errorf("bundle payload integratedTime is missing")
	}
	if b.Payload.Body == nil {
		return fmt.Errorf("bundle payload body is missing")
	}
	if b.SignedEntryTimestamp == nil {
		return fmt.Errorf("signed entry timestamp is missing")
	}
	return nil
}

func (b *payloadBody) validate() error {
	if b.APIVersion == nil {
		return fmt.Errorf("body apiVersion is missing")
	}
	if b.Kind == nil {
		return fmt.Errorf("body kind is missing")
	}
	return nil
}

// getVerificationMaterialTlogEntries returns the verification material
// transparency log entries from the simple signing layer
func getVerificationMaterialTlogEntries(manifestLayer ocispec.Descriptor) ([]*protorekor.TransparencyLogEntry, error) {
	// 1. Get the bundle annotation from the manifest layer.
	annotation, exists := manifestLayer.Annotations[annotationKeyBundle]
	if !exists {
		return nil, fmt.Errorf("bundle annotation not found")
	}

	// 2. Unmarshal the bundle annotation into a bundleAnnotation.
	var bundle bundleAnnotation
	if err := json.Unmarshal([]byte(annotation), &bundle); err != nil {
		return nil, fmt.Errorf("error unmarshaling bundle annotation: %w", err)
	}
	if err := bundle.validate(); err != nil {
		return nil, fmt.Errorf("bundle validation failed: %w", err)
	}
	logID, err := hex.DecodeString(*bundle.Payload.LogID)
	if err != nil {
		return nil, fmt.Errorf("error decoding logID: %w", err)
	}
	signedEntryTimestamp, err := base64.StdEncoding.DecodeString(*bundle.SignedEntryTimestamp)
	if err != nil {
		return nil, fmt.Errorf("error decoding signedEntryTimestamp: %w", err)
	}

	// 3. Decode the body from the bundle payload.
	bodyDecoded, err := base64.StdEncoding.DecodeString(*bundle.Payload.Body)
	if err != nil {
		return nil, err
	}
	var body payloadBody
	if err := json.Unmarshal(bodyDecoded, &body); err != nil {
		return nil, fmt.Errorf("error unmarshaling body: %w", err)
	}
	if err := body.validate(); err != nil {
		return nil, fmt.Errorf("body validation failed: %w", err)
	}

	// 4. Construct the transparency log entry.
	return []*protorekor.TransparencyLogEntry{
		{
			LogIndex: int64(*bundle.Payload.LogIndex),
			LogId: &protocommon.LogId{
				KeyId: logID,
			},
			KindVersion: &protorekor.KindVersion{
				Kind:    *body.Kind,
				Version: *body.APIVersion,
			},
			IntegratedTime: int64(*bundle.Payload.IntegratedTime),
			InclusionPromise: &protorekor.InclusionPromise{
				SignedEntryTimestamp: signedEntryTimestamp,
			},
			CanonicalizedBody: bodyDecoded,
		},
	}, nil
}

// getBundleMsgSignature returns the bundle message signature from the simple
// signing layer
func getBundleMsgSignature(simpleSigningLayer ocispec.Descriptor) (*protobundle.Bundle_MessageSignature, error) {
	// 1. Get the message digest algorithm
	var msgHashAlg protocommon.HashAlgorithm
	switch alg := simpleSigningLayer.Digest.Algorithm(); alg {
	case digest.SHA256:
		msgHashAlg = protocommon.HashAlgorithm_SHA2_256
	default:
		return nil, fmt.Errorf("unknown digest algorithm: %s", alg)
	}
	// 2. Get the message digest
	digest, err := hex.DecodeString(simpleSigningLayer.Digest.Encoded())
	if err != nil {
		return nil, fmt.Errorf("error decoding digest: %w", err)
	}
	// 3. Get the signature
	s := simpleSigningLayer.Annotations[annotationKeySignature]
	sig, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("error decoding manSig: %w", err)
	}
	// Construct the bundle message signature
	return &protobundle.Bundle_MessageSignature{
		MessageSignature: &protocommon.MessageSignature{
			MessageDigest: &protocommon.HashOutput{
				Algorithm: msgHashAlg,
				Digest:    digest,
			},
			Signature: sig,
		},
	}, nil
}

// getSignatureDescriptors extracts the signature descriptors from the signature
// manifest.
func getSignatureDescriptors(ctx context.Context, store ratify.Store, repo string, artifactDesc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	manifestBytes, err := store.FetchManifest(ctx, repo, artifactDesc)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch manifest for artifact: %w", err)
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, fmt.Errorf("failed to unmarshal manifest: %w", err)
	}
	if manifest.MediaType != ocispec.MediaTypeImageManifest {
		return nil, fmt.Errorf("expected media type %s, got %s", ocispec.MediaTypeImageManifest, manifest.MediaType)
	}

	var descriptors []ocispec.Descriptor
	for _, layer := range manifest.Layers {
		if layer.MediaType == mediaTypeSimpleSigning {
			descriptors = append(descriptors, layer)
		}
	}

	return descriptors, nil
}

// createTrustedPublicKeyMaterial creates a trusted material from a public key
// with validity period.
func createTrustedPublicKeyMaterial(config *PublicKeyConfig) root.TrustedMaterial {
	return root.NewTrustedPublicKeyMaterial(func(string) (root.TimeConstrainedVerifier, error) {
		verifier, err := signature.LoadVerifier(config.PublicKey, config.SignatureAlgorithm)
		if err != nil {
			return nil, err
		}
		return root.NewExpiringKey(verifier, config.ValidityPeriodStart, config.ValidityPeriodEnd), nil
	})
}

// layerReport is a report generated for a single simple signing
// layer.
type layerReport struct {
	// Digest is the digest of the simple signing layer.
	Digest string `json:"digest"`

	// Succeeded indicates whether the signature verification succeeded.
	Succeeded bool `json:"succeeded"`

	// Error contains the error if the verification failed.
	Error error

	// VerificationResult contains the verification result if the verification
	// succeeded.
	VerificationResult *verify.VerificationResult `json:"verificationResult,omitempty"`
}

// MarshalJSON deals with the Error field to ensure it is serialized correctly.
func (b *layerReport) MarshalJSON() ([]byte, error) {
	type Alias layerReport
	var errorStr string
	if b.Error != nil {
		errorStr = b.Error.Error()
	}
	return json.Marshal(struct {
		Alias
		Error string `json:"error,omitempty"`
	}{
		Alias: Alias(*b),
		Error: errorStr,
	})
}
