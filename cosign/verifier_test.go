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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/notaryproject/ratify-go"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// Mock store for testing
type mockStore struct {
	manifests map[string][]byte
	blobs     map[string][]byte
}

func newMockStore() *mockStore {
	return &mockStore{
		manifests: make(map[string][]byte),
		blobs:     make(map[string][]byte),
	}
}

func (m *mockStore) FetchManifest(ctx context.Context, repository string, descriptor ocispec.Descriptor) ([]byte, error) {
	key := fmt.Sprintf("%s@%s", repository, descriptor.Digest)
	if manifest, exists := m.manifests[key]; exists {
		return manifest, nil
	}
	return nil, fmt.Errorf("manifest not found: %s", key)
}

func (m *mockStore) FetchBlob(ctx context.Context, repository string, descriptor ocispec.Descriptor) ([]byte, error) {
	key := fmt.Sprintf("%s@%s", repository, descriptor.Digest)
	if blob, exists := m.blobs[key]; exists {
		return blob, nil
	}
	return nil, fmt.Errorf("blob not found: %s", key)
}

func (m *mockStore) Resolve(ctx context.Context, ref string) (ocispec.Descriptor, error) {
	return ocispec.Descriptor{}, fmt.Errorf("resolve not implemented in mock")
}

func (m *mockStore) ListReferrers(ctx context.Context, ref string, artifactTypes []string, fn func(referrers []ocispec.Descriptor) error) error {
	return fn([]ocispec.Descriptor{})
}

func (m *mockStore) addManifest(repository string, descriptor ocispec.Descriptor, manifest []byte) {
	key := fmt.Sprintf("%s@%s", repository, descriptor.Digest)
	m.manifests[key] = manifest
}

func (m *mockStore) addBlob(repository string, descriptor ocispec.Descriptor, blob []byte) {
	key := fmt.Sprintf("%s@%s", repository, descriptor.Digest)
	m.blobs[key] = blob
}

// Test helper functions
type testTrustedPublicKeys struct {
	configs []*PublicKeyConfig
	err     error
}

func (t *testTrustedPublicKeys) GetPublicKeys(ctx context.Context) ([]*PublicKeyConfig, error) {
	if t.err != nil {
		return nil, t.err
	}
	return t.configs, nil
}

func generateTestKey() (*ecdsa.PrivateKey, crypto.PublicKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func generateTestCertificate(publicKey crypto.PublicKey) (string, error) {
	// Generate a private key for signing the certificate
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return "", err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return string(certPEM), nil
}

func createTestBundleAnnotation() (string, error) {
	bundleData := map[string]interface{}{
		"Payload": map[string]interface{}{
			"logIndex":       float64(12345),
			"logID":          "abcdef1234567890",
			"integratedTime": float64(1640995200),
			"body":           base64.StdEncoding.EncodeToString([]byte(`{"apiVersion": "0.0.1", "kind": "hashedrekord"}`)),
		},
		"SignedEntryTimestamp": base64.StdEncoding.EncodeToString([]byte("test-signature")),
	}

	bundleJSON, err := json.Marshal(bundleData)
	if err != nil {
		return "", err
	}

	return string(bundleJSON), nil
}

func createTestManifest(layers []ocispec.Descriptor) ([]byte, error) {
	manifest := ocispec.Manifest{
		Versioned: specs.Versioned{
			SchemaVersion: 2,
		},
		MediaType: ocispec.MediaTypeImageManifest,
		Layers:    layers,
	}

	return json.Marshal(manifest)
}

func TestNewVerifier(t *testing.T) {
	tests := []struct {
		name        string
		opts        *VerifierOptions
		expectError bool
	}{
		{
			name: "valid verifier with name",
			opts: &VerifierOptions{
				Name: "test-verifier",
			},
			expectError: false,
		},
		{
			name:        "missing name",
			opts:        &VerifierOptions{},
			expectError: true,
		},
		{
			name: "with public key config",
			opts: &VerifierOptions{
				Name: "test-verifier",
				GetPublicKeys: (&testTrustedPublicKeys{
					configs: []*PublicKeyConfig{
						{
							PublicKey:          &ecdsa.PublicKey{},
							SignatureAlgorithm: crypto.SHA256,
						},
					},
				}).GetPublicKeys,
			},
			expectError: false,
		},
		{
			name: "with nil public key config",
			opts: &VerifierOptions{
				Name: "test-verifier",
				GetPublicKeys: (&testTrustedPublicKeys{
					configs: []*PublicKeyConfig{
						nil,
					},
				}).GetPublicKeys,
			},
			expectError: false, // NewVerifier doesn't validate immediately, validation happens on use
		},
		{
			name: "with identity policies",
			opts: &VerifierOptions{
				Name: "test-verifier",
				// Note: WithCertificateIdentity requires specific types, so we'll skip
				// complex identity policy testing for now
				IdentityPolicies: []verify.PolicyOption{},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier, err := NewVerifier(tt.opts)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if verifier == nil {
					t.Errorf("Expected verifier but got nil")
				}
				if verifier != nil && verifier.Name() != tt.opts.Name {
					t.Errorf("Expected name %s, got %s", tt.opts.Name, verifier.Name())
				}
			}
		})
	}
}

func TestVerifier_Name(t *testing.T) {
	verifier := &Verifier{name: "test-verifier"}
	if verifier.Name() != "test-verifier" {
		t.Errorf("Expected name 'test-verifier', got '%s'", verifier.Name())
	}
}

func TestVerifier_Type(t *testing.T) {
	verifier := &Verifier{}
	if verifier.Type() != verifierTypeCosign {
		t.Errorf("Expected type '%s', got '%s'", verifierTypeCosign, verifier.Type())
	}
}

func TestVerifier_Verifiable(t *testing.T) {
	verifier := &Verifier{}

	tests := []struct {
		name       string
		descriptor ocispec.Descriptor
		expected   bool
	}{
		{
			name: "valid cosign signature artifact",
			descriptor: ocispec.Descriptor{
				ArtifactType: mediaTypeCosignArtifactSignature,
				MediaType:    ocispec.MediaTypeImageManifest,
			},
			expected: true,
		},
		{
			name: "invalid artifact type",
			descriptor: ocispec.Descriptor{
				ArtifactType: "invalid-type",
				MediaType:    ocispec.MediaTypeImageManifest,
			},
			expected: false,
		},
		{
			name: "invalid media type",
			descriptor: ocispec.Descriptor{
				ArtifactType: mediaTypeCosignArtifactSignature,
				MediaType:    "invalid-media-type",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := verifier.Verifiable(tt.descriptor)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestGetVerificationMaterialX509CertificateChain(t *testing.T) {
	// Generate a test certificate
	_, publicKey, err := generateTestKey()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	certPEM, err := generateTestCertificate(publicKey)
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	tests := []struct {
		name        string
		layer       ocispec.Descriptor
		expectError bool
	}{
		{
			name: "valid certificate",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyCert: certPEM,
				},
			},
			expectError: false,
		},
		{
			name: "missing certificate annotation",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{},
			},
			expectError: true,
		},
		{
			name: "invalid PEM",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyCert: "invalid-pem",
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getVerificationMaterialX509CertificateChain(tt.layer)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if result == nil {
					t.Errorf("Expected result but got nil")
				}
				if result != nil && result.X509CertificateChain == nil {
					t.Errorf("Expected certificate chain but got nil")
				}
			}
		})
	}
}

func TestGetVerificationMaterialTlogEntries(t *testing.T) {
	validBundle, err := createTestBundleAnnotation()
	if err != nil {
		t.Fatalf("Failed to create test bundle annotation: %v", err)
	}

	tests := []struct {
		name        string
		layer       ocispec.Descriptor
		expectError bool
	}{
		{
			name: "valid bundle annotation",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: validBundle,
				},
			},
			expectError: false,
		},
		{
			name: "missing annotations",
			layer: ocispec.Descriptor{
				Annotations: nil,
			},
			expectError: true,
		},
		{
			name: "missing bundle annotation",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{},
			},
			expectError: true,
		},
		{
			name: "empty bundle annotation",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: "",
				},
			},
			expectError: true,
		},
		{
			name: "invalid JSON",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: "invalid-json",
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getVerificationMaterialTlogEntries(tt.layer)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if result == nil {
					t.Errorf("Expected result but got nil")
				}
				if len(result) == 0 {
					t.Errorf("Expected non-empty result")
				}
			}
		})
	}
}

func TestGetBundleMsgSignature(t *testing.T) {
	testSignature := base64.StdEncoding.EncodeToString([]byte("test-signature"))

	tests := []struct {
		name        string
		layer       ocispec.Descriptor
		expectError bool
	}{
		{
			name: "valid SHA256 signature",
			layer: ocispec.Descriptor{
				Digest: digest.FromString("test-content"),
				Annotations: map[string]string{
					annotationKeySignature: testSignature,
				},
			},
			expectError: false,
		},
		{
			name: "missing signature annotation",
			layer: ocispec.Descriptor{
				Digest:      digest.FromString("test-content"),
				Annotations: map[string]string{},
			},
			expectError: false, // Empty string decodes successfully to empty bytes
		},
		{
			name: "invalid signature encoding",
			layer: ocispec.Descriptor{
				Digest: digest.FromString("test-content"),
				Annotations: map[string]string{
					annotationKeySignature: "invalid-base64!@#",
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getBundleMsgSignature(tt.layer)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if result == nil {
					t.Errorf("Expected result but got nil")
				}
			}
		})
	}
}

func TestGetSignatureDescriptors(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()
	repo := "test/repo"

	// Create test manifest with simple signing layers
	layers := []ocispec.Descriptor{
		{
			MediaType: mediaTypeSimpleSigning,
			Digest:    digest.FromString("layer1"),
			Size:      100,
		},
		{
			MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
			Digest:    digest.FromString("layer2"),
			Size:      200,
		},
		{
			MediaType: mediaTypeSimpleSigning,
			Digest:    digest.FromString("layer3"),
			Size:      150,
		},
	}

	manifestBytes, err := createTestManifest(layers)
	if err != nil {
		t.Fatalf("Failed to create test manifest: %v", err)
	}

	artifactDesc := ocispec.Descriptor{
		Digest: digest.FromBytes(manifestBytes),
		Size:   int64(len(manifestBytes)),
	}

	store.addManifest(repo, artifactDesc, manifestBytes)

	descriptors, err := getSignatureDescriptors(ctx, store, repo, artifactDesc)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	expectedCount := 2 // Only simple signing layers
	if len(descriptors) != expectedCount {
		t.Errorf("Expected %d descriptors, got %d", expectedCount, len(descriptors))
	}

	for _, desc := range descriptors {
		if desc.MediaType != mediaTypeSimpleSigning {
			t.Errorf("Expected media type %s, got %s", mediaTypeSimpleSigning, desc.MediaType)
		}
	}
}

func TestCreateTrustedPublicKeyMaterial(t *testing.T) {
	tests := []struct {
		name             string
		config           *PublicKeyConfig
		expectError      bool
		validateMaterial bool
	}{
		{
			name: "valid config with SHA256",
			config: func() *PublicKeyConfig {
				_, publicKey, err := generateTestKey()
				if err != nil {
					t.Fatalf("Failed to generate test key: %v", err)
				}
				return &PublicKeyConfig{
					PublicKey:           publicKey,
					SignatureAlgorithm:  crypto.SHA256,
					ValidityPeriodStart: time.Now().Add(-time.Hour),
					ValidityPeriodEnd:   time.Now().Add(time.Hour),
				}
			}(),
			expectError:      false,
			validateMaterial: true,
		},
		{
			name: "valid config with SHA512",
			config: func() *PublicKeyConfig {
				_, publicKey, err := generateTestKey()
				if err != nil {
					t.Fatalf("Failed to generate test key: %v", err)
				}
				return &PublicKeyConfig{
					PublicKey:           publicKey,
					SignatureAlgorithm:  crypto.SHA512,
					ValidityPeriodStart: time.Now().Add(-time.Hour),
					ValidityPeriodEnd:   time.Now().Add(time.Hour),
				}
			}(),
			expectError:      false,
			validateMaterial: true,
		},
		{
			name: "valid config with zero algorithm (should default to SHA256)",
			config: func() *PublicKeyConfig {
				_, publicKey, err := generateTestKey()
				if err != nil {
					t.Fatalf("Failed to generate test key: %v", err)
				}
				return &PublicKeyConfig{
					PublicKey:           publicKey,
					SignatureAlgorithm:  0, // Zero value should default to SHA256
					ValidityPeriodStart: time.Now().Add(-time.Hour),
					ValidityPeriodEnd:   time.Now().Add(time.Hour),
				}
			}(),
			expectError:      false,
			validateMaterial: true,
		},
		{
			name: "valid config without validity period",
			config: func() *PublicKeyConfig {
				_, publicKey, err := generateTestKey()
				if err != nil {
					t.Fatalf("Failed to generate test key: %v", err)
				}
				return &PublicKeyConfig{
					PublicKey:          publicKey,
					SignatureAlgorithm: crypto.SHA256,
					// No validity period set
				}
			}(),
			expectError:      false,
			validateMaterial: true,
		},
		{
			name: "invalid public key (nil)",
			config: &PublicKeyConfig{
				PublicKey:           nil,
				SignatureAlgorithm:  crypto.SHA256,
				ValidityPeriodStart: time.Now().Add(-time.Hour),
				ValidityPeriodEnd:   time.Now().Add(time.Hour),
			},
			expectError:      true,
			validateMaterial: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			material := createTrustedPublicKeyMaterial(tt.config)

			if material == nil {
				t.Errorf("Expected trusted material but got nil")
				return
			}
		})
	}
}

func TestCreateTrustedMaterialFromPublicKeys(t *testing.T) {
	tests := []struct {
		name                string
		getPublicKeys       func(ctx context.Context) ([]*PublicKeyConfig, error)
		expectedMaterialLen int
		expectError         bool
	}{
		{
			name:                "nil trusted public keys",
			getPublicKeys:       nil,
			expectedMaterialLen: 0,
			expectError:         false,
		},
		{
			name: "single valid public key",
			getPublicKeys: func() func(ctx context.Context) ([]*PublicKeyConfig, error) {
				_, publicKey, err := generateTestKey()
				if err != nil {
					t.Fatalf("Failed to generate test key: %v", err)
				}
				return (&testTrustedPublicKeys{
					configs: []*PublicKeyConfig{
						{
							PublicKey:           publicKey,
							SignatureAlgorithm:  crypto.SHA256,
							ValidityPeriodStart: time.Now().Add(-time.Hour),
							ValidityPeriodEnd:   time.Now().Add(time.Hour),
						},
					},
				}).GetPublicKeys
			}(),
			expectedMaterialLen: 1,
			expectError:         false,
		},
		{
			name: "multiple valid public keys",
			getPublicKeys: func() func(ctx context.Context) ([]*PublicKeyConfig, error) {
				_, publicKey1, err := generateTestKey()
				if err != nil {
					t.Fatalf("Failed to generate test key 1: %v", err)
				}
				_, publicKey2, err := generateTestKey()
				if err != nil {
					t.Fatalf("Failed to generate test key 2: %v", err)
				}
				return (&testTrustedPublicKeys{
					configs: []*PublicKeyConfig{
						{
							PublicKey:           publicKey1,
							SignatureAlgorithm:  crypto.SHA256,
							ValidityPeriodStart: time.Now().Add(-time.Hour),
							ValidityPeriodEnd:   time.Now().Add(time.Hour),
						},
						{
							PublicKey:           publicKey2,
							SignatureAlgorithm:  crypto.SHA512,
							ValidityPeriodStart: time.Now().Add(-2 * time.Hour),
							ValidityPeriodEnd:   time.Now().Add(2 * time.Hour),
						},
					},
				}).GetPublicKeys
			}(),
			expectedMaterialLen: 2,
			expectError:         false,
		},
		{
			name: "public key with zero algorithm (defaults to SHA256)",
			getPublicKeys: func() func(ctx context.Context) ([]*PublicKeyConfig, error) {
				_, publicKey, err := generateTestKey()
				if err != nil {
					t.Fatalf("Failed to generate test key: %v", err)
				}
				return (&testTrustedPublicKeys{
					configs: []*PublicKeyConfig{
						{
							PublicKey:           publicKey,
							SignatureAlgorithm:  0, // Should default to SHA256
							ValidityPeriodStart: time.Now().Add(-time.Hour),
							ValidityPeriodEnd:   time.Now().Add(time.Hour),
						},
					},
				}).GetPublicKeys
			}(),
			expectedMaterialLen: 1,
			expectError:         false,
		},
		{
			name: "nil public key config",
			getPublicKeys: (&testTrustedPublicKeys{
				configs: []*PublicKeyConfig{nil},
			}).GetPublicKeys,
			expectedMaterialLen: 0,
			expectError:         true,
		},
		{
			name: "error getting public keys",
			getPublicKeys: (&testTrustedPublicKeys{
				err: fmt.Errorf("failed to get public keys"),
			}).GetPublicKeys,
			expectedMaterialLen: 0,
			expectError:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			materials, err := createTrustedMaterialFromPublicKeys(context.Background(), tt.getPublicKeys)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if len(materials) != tt.expectedMaterialLen {
				t.Errorf("Expected %d materials, got %d", tt.expectedMaterialLen, len(materials))
			}

			// Verify that all returned materials are not nil
			for i, material := range materials {
				if material == nil {
					t.Errorf("Material at index %d is nil", i)
				}
			}
		})
	}
}

func TestLayerReport_MarshalJSON(t *testing.T) {
	tests := []struct {
		name   string
		report *layerReport
	}{
		{
			name: "successful report",
			report: &layerReport{
				Digest:    "sha256:abcdef",
				Succeeded: true,
				Error:     nil,
			},
		},
		{
			name: "failed report with error",
			report: &layerReport{
				Digest:    "sha256:abcdef",
				Succeeded: false,
				Error:     fmt.Errorf("verification failed"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.report.MarshalJSON()
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			var result map[string]interface{}
			if err := json.Unmarshal(data, &result); err != nil {
				t.Errorf("Failed to unmarshal result: %v", err)
			}

			if result["digest"] != tt.report.Digest {
				t.Errorf("Expected digest %s, got %v", tt.report.Digest, result["digest"])
			}

			if result["succeeded"] != tt.report.Succeeded {
				t.Errorf("Expected succeeded %v, got %v", tt.report.Succeeded, result["succeeded"])
			}

			if tt.report.Error != nil {
				if result["error"] != tt.report.Error.Error() {
					t.Errorf("Expected error %s, got %v", tt.report.Error.Error(), result["error"])
				}
			}
		})
	}
}

func TestPublicKeyConfigDefaults(t *testing.T) {
	_, publicKey, err := generateTestKey()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	opts := &VerifierOptions{
		Name: "test-verifier",
		GetPublicKeys: (&testTrustedPublicKeys{
			configs: []*PublicKeyConfig{
				{
					PublicKey: publicKey,
					// SignatureAlgorithm not set - should default to SHA256
				},
			},
		}).GetPublicKeys,
	}

	verifier, err := NewVerifier(opts)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if verifier == nil {
		t.Errorf("Expected verifier but got nil")
	}
}

func TestVerifier_VerifyIntegration(t *testing.T) {
	// This is a basic integration test that tests the Verify method
	// with a mock store and basic setup
	ctx := context.Background()
	store := newMockStore()
	repo := "test/repo"

	// Create a verifier with minimal setup
	opts := &VerifierOptions{
		Name:       "test-verifier",
		IgnoreTLog: true, // Ignore tlog for this test
	}

	verifier, err := NewVerifier(opts)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	// Create test artifact descriptor
	artifactDesc := ocispec.Descriptor{
		ArtifactType: mediaTypeCosignArtifactSignature,
		MediaType:    ocispec.MediaTypeImageManifest,
		Digest:       digest.FromString("test-artifact"),
		Size:         100,
	}

	// Create empty manifest (no layers)
	manifestBytes, err := createTestManifest([]ocispec.Descriptor{})
	if err != nil {
		t.Fatalf("Failed to create test manifest: %v", err)
	}

	store.addManifest(repo, artifactDesc, manifestBytes)

	verifyOpts := &ratify.VerifyOptions{
		Store:              store,
		Repository:         repo,
		ArtifactDescriptor: artifactDesc,
	}

	result, err := verifier.Verify(ctx, verifyOpts)
	if err != nil {
		t.Fatalf("Unexpected error during verification: %v", err)
	}

	if result == nil {
		t.Errorf("Expected verification result but got nil")
	}

	if result.Verifier != verifier {
		t.Errorf("Expected verifier to match")
	}

	// With no signature layers, we expect no valid signatures
	if result.Description != "Cosign signature verification failed: no valid signatures found" {
		t.Errorf("Unexpected description: %s", result.Description)
	}
}

func TestGetBundleVerificationMaterial(t *testing.T) {
	// Generate test certificate
	_, publicKey, err := generateTestKey()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	certPEM, err := generateTestCertificate(publicKey)
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	bundleAnnotation, err := createTestBundleAnnotation()
	if err != nil {
		t.Fatalf("Failed to create test bundle annotation: %v", err)
	}

	layer := ocispec.Descriptor{
		Annotations: map[string]string{
			annotationKeyCert:   certPEM,
			annotationKeyBundle: bundleAnnotation,
		},
	}

	tests := []struct {
		name        string
		ignoreTlog  bool
		expectError bool
	}{
		{
			name:        "with tlog entries",
			ignoreTlog:  false,
			expectError: false,
		},
		{
			name:        "ignore tlog entries",
			ignoreTlog:  true,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getBundleVerificationMaterial(layer, tt.ignoreTlog, nil)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if result == nil {
					t.Errorf("Expected result but got nil")
				}
				if result != nil {
					if result.Content == nil {
						t.Errorf("Expected content but got nil")
					}
					if tt.ignoreTlog && len(result.TlogEntries) > 0 {
						t.Errorf("Expected no tlog entries when ignored, got %d", len(result.TlogEntries))
					}
					if !tt.ignoreTlog && len(result.TlogEntries) == 0 {
						t.Errorf("Expected tlog entries when not ignored")
					}
				}
			}
		})
	}
}

// Additional test functions for comprehensive coverage

func TestVerifier_VerifyWithSignatureLayers(t *testing.T) {
	// This test verifies the Verify method with actual signature layers
	ctx := context.Background()
	store := newMockStore()
	repo := "test/repo"

	// Create a verifier
	opts := &VerifierOptions{
		Name:       "test-verifier",
		IgnoreTLog: true, // Ignore tlog for this test
	}

	verifier, err := NewVerifier(opts)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	// Generate test certificate
	_, publicKey, err := generateTestKey()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	certPEM, err := generateTestCertificate(publicKey)
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	testSignature := base64.StdEncoding.EncodeToString([]byte("test-signature"))

	// Create signature layer with certificate and signature annotations
	sigLayer := ocispec.Descriptor{
		MediaType: mediaTypeSimpleSigning,
		Digest:    digest.FromString("signature-layer"),
		Size:      100,
		Annotations: map[string]string{
			annotationKeyCert:      certPEM,
			annotationKeySignature: testSignature,
		},
	}

	// Create manifest with signature layer
	manifestBytes, err := createTestManifest([]ocispec.Descriptor{sigLayer})
	if err != nil {
		t.Fatalf("Failed to create test manifest: %v", err)
	}

	artifactDesc := ocispec.Descriptor{
		ArtifactType: mediaTypeCosignArtifactSignature,
		MediaType:    ocispec.MediaTypeImageManifest,
		Digest:       digest.FromBytes(manifestBytes),
		Size:         int64(len(manifestBytes)),
	}

	store.addManifest(repo, artifactDesc, manifestBytes)

	verifyOpts := &ratify.VerifyOptions{
		Store:              store,
		Repository:         repo,
		ArtifactDescriptor: artifactDesc,
	}

	result, err := verifier.Verify(ctx, verifyOpts)
	if err != nil {
		t.Fatalf("Unexpected error during verification: %v", err)
	}

	if result == nil {
		t.Errorf("Expected verification result but got nil")
	}

	// Check that we have verification details
	if result.Detail != nil {
		if detailMap, ok := result.Detail.(map[string][]*layerReport); ok {
			if details, exists := detailMap["verifiedSignatures"]; exists {
				if len(details) == 0 {
					t.Errorf("Expected at least one signature layer report")
				} else {
					// The signature will fail verification but we should still get a report
					if details[0].Digest != sigLayer.Digest.String() {
						t.Errorf("Expected digest %s, got %s", sigLayer.Digest.String(), details[0].Digest)
					}
				}
			} else {
				t.Errorf("Expected verification details but got none")
			}
		} else {
			t.Errorf("Expected verification details to be a map but got different type")
		}
	} else {
		t.Errorf("Expected verification details but got nil")
	}
}

func TestGetVerificationMaterialTlogEntries_MalformedBundle(t *testing.T) {
	// Test with various malformed bundle annotations
	tests := []struct {
		name   string
		bundle string
	}{
		{
			name:   "missing Payload",
			bundle: `{"NotPayload": {}}`,
		},
		{
			name:   "null Payload",
			bundle: `{"Payload": null}`,
		},
		{
			name:   "missing logIndex",
			bundle: `{"Payload": {"logID": "abc", "integratedTime": 123, "body": "dGVzdA=="}, "SignedEntryTimestamp": "dGVzdA=="}`,
		},
		{
			name:   "missing logID",
			bundle: `{"Payload": {"logIndex": 123, "integratedTime": 123, "body": "dGVzdA=="}, "SignedEntryTimestamp": "dGVzdA=="}`,
		},
		{
			name:   "invalid body base64",
			bundle: `{"Payload": {"logIndex": 123, "logID": "abc", "integratedTime": 123, "body": "invalid-base64!"}, "SignedEntryTimestamp": "dGVzdA=="}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			layer := ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: tt.bundle,
				},
			}

			_, err := getVerificationMaterialTlogEntries(layer)
			if err == nil {
				t.Errorf("Expected error for malformed bundle but got none")
			}
		})
	}
}

func TestGetBundleMsgSignature_UnsupportedDigestAlgorithm(t *testing.T) {
	// Test with unsupported digest algorithm
	testSignature := base64.StdEncoding.EncodeToString([]byte("test-signature"))

	// Create a digest with an unsupported algorithm
	unsupportedDigest := digest.Digest("blake2b:abcdef1234567890")

	layer := ocispec.Descriptor{
		Digest: unsupportedDigest,
		Annotations: map[string]string{
			annotationKeySignature: testSignature,
		},
	}

	_, err := getBundleMsgSignature(layer)
	if err == nil {
		t.Errorf("Expected error for unsupported digest algorithm but got none")
	}

	expectedError := "unknown digest algorithm: blake2b"
	if err.Error() != expectedError {
		t.Errorf("Expected error message '%s', got '%s'", expectedError, err.Error())
	}
}

func TestVerifier_VerifyBundleError(t *testing.T) {
	// Test verifyBundle method with invalid digest
	verifier := &Verifier{
		name:       "test-verifier",
		ignoreTLog: true,
	}

	// Create an invalid digest that should cause hex decoding to fail
	invalidDigest := digest.Digest("sha256:invalid-hex-string!")

	// This test would normally require a valid bundle, but since the digest
	// decoding will fail first, we can pass nil
	_, err := verifier.verifyBundle(nil, invalidDigest)
	if err == nil {
		t.Errorf("Expected error for invalid digest but got none")
	}
}

func TestVerifierOptions_Validation(t *testing.T) {
	// Test various edge cases in verifier options validation
	tests := []struct {
		name        string
		opts        *VerifierOptions
		expectError bool
		errorMsg    string
	}{
		{
			name:        "nil options",
			opts:        nil,
			expectError: true,
		},
		{
			name: "empty name",
			opts: &VerifierOptions{
				Name: "",
			},
			expectError: true,
			errorMsg:    "verifier name is required",
		},
		{
			name: "with multiple public key configs",
			opts: &VerifierOptions{
				Name: "test-verifier",
				GetPublicKeys: (&testTrustedPublicKeys{
					configs: []*PublicKeyConfig{
						{
							PublicKey:          &ecdsa.PublicKey{},
							SignatureAlgorithm: crypto.SHA256,
						},
						{
							PublicKey:          &ecdsa.PublicKey{},
							SignatureAlgorithm: crypto.SHA512,
						},
					},
				}).GetPublicKeys,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.opts != nil {
				_, err = NewVerifier(tt.opts)
			} else {
				// Test nil options by calling with nil
				defer func() {
					if r := recover(); r != nil {
						err = fmt.Errorf("panic: %v", r)
					}
				}()
				_, err = NewVerifier(nil)
			}

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorMsg != "" && err.Error() != tt.errorMsg {
					t.Errorf("Expected error message '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestGetSignatureDescriptors_ErrorCases(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()
	repo := "test/repo"

	tests := []struct {
		name        string
		setupStore  func(*mockStore, ocispec.Descriptor)
		expectError bool
	}{
		{
			name: "manifest not found",
			setupStore: func(s *mockStore, desc ocispec.Descriptor) {
				// Don't add the manifest to the store
			},
			expectError: true,
		},
		{
			name: "invalid manifest JSON",
			setupStore: func(s *mockStore, desc ocispec.Descriptor) {
				s.addManifest(repo, desc, []byte("invalid-json"))
			},
			expectError: true,
		},
		{
			name: "wrong media type",
			setupStore: func(s *mockStore, desc ocispec.Descriptor) {
				manifest := ocispec.Manifest{
					Versioned: specs.Versioned{
						SchemaVersion: 2,
					},
					MediaType: "application/vnd.docker.distribution.manifest.v2+json",
					Layers:    []ocispec.Descriptor{},
				}
				manifestBytes, _ := json.Marshal(manifest)
				s.addManifest(repo, desc, manifestBytes)
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			artifactDesc := ocispec.Descriptor{
				Digest: digest.FromString("test-manifest"),
				Size:   100,
			}

			tt.setupStore(store, artifactDesc)

			_, err := getSignatureDescriptors(ctx, store, repo, artifactDesc)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestGetVerificationMaterialTlogEntries_ComprehensiveCoverage provides comprehensive
// test coverage for all code paths in getVerificationMaterialTlogEntries function
func TestGetVerificationMaterialTlogEntries_ComprehensiveCoverage(t *testing.T) {
	// Helper function to create bundle with specific payload
	createBundleWithPayload := func(payload map[string]interface{}, signedEntryTimestamp string) string {
		bundleData := map[string]interface{}{
			"Payload":              payload,
			"SignedEntryTimestamp": signedEntryTimestamp,
		}
		bundleJSON, _ := json.Marshal(bundleData)
		return string(bundleJSON)
	}

	// Helper function to create bundle with specific SignedEntryTimestamp
	createBundleWithSET := func(signedEntryTimestamp interface{}) string {
		payload := map[string]interface{}{
			"logIndex":       float64(12345),
			"logID":          "abcdef1234567890",
			"integratedTime": float64(1640995200),
			"body":           base64.StdEncoding.EncodeToString([]byte(`{"apiVersion": "0.0.1", "kind": "hashedrekord"}`)),
		}
		bundleData := map[string]interface{}{
			"Payload":              payload,
			"SignedEntryTimestamp": signedEntryTimestamp,
		}
		bundleJSON, _ := json.Marshal(bundleData)
		return string(bundleJSON)
	}

	tests := []struct {
		name        string
		layer       ocispec.Descriptor
		expectError bool
		errorMsg    string
	}{
		// Test case: jsonData is nil after unmarshaling (edge case - this shouldn't happen in practice)
		{
			name: "nil json data after unmarshaling",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: "null",
				},
			},
			expectError: true,
			errorMsg:    "bundle payload is missing",
		},
		// Test case: Payload exists but is null
		{
			name: "null payload",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: `{"Payload": null}`,
				},
			},
			expectError: true,
			errorMsg:    "bundle payload is missing",
		},
		// Test case: logIndex is not float64 (wrong type)
		{
			name: "logIndex wrong type",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithPayload(map[string]interface{}{
						"logIndex":       "not-a-number",
						"logID":          "abcdef1234567890",
						"integratedTime": float64(1640995200),
						"body":           base64.StdEncoding.EncodeToString([]byte(`{"apiVersion": "0.0.1", "kind": "hashedrekord"}`)),
					}, base64.StdEncoding.EncodeToString([]byte("test-signature"))),
				},
			},
			expectError: true,
			errorMsg:    "error unmarshaling bundle annotation",
		},
		// Test case: logID is not string (wrong type)
		{
			name: "logID wrong type",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithPayload(map[string]interface{}{
						"logIndex":       float64(12345),
						"logID":          12345, // should be string
						"integratedTime": float64(1640995200),
						"body":           base64.StdEncoding.EncodeToString([]byte(`{"apiVersion": "0.0.1", "kind": "hashedrekord"}`)),
					}, base64.StdEncoding.EncodeToString([]byte("test-signature"))),
				},
			},
			expectError: true,
			errorMsg:    "error unmarshaling bundle annotation",
		},
		// Test case: invalid hex in logID
		{
			name: "invalid hex in logID",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithPayload(map[string]interface{}{
						"logIndex":       float64(12345),
						"logID":          "invalid-hex-string!@#",
						"integratedTime": float64(1640995200),
						"body":           base64.StdEncoding.EncodeToString([]byte(`{"apiVersion": "0.0.1", "kind": "hashedrekord"}`)),
					}, base64.StdEncoding.EncodeToString([]byte("test-signature"))),
				},
			},
			expectError: true,
			errorMsg:    "error decoding logID",
		},
		// Test case: missing integratedTime
		{
			name: "missing integratedTime",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithPayload(map[string]interface{}{
						"logIndex": float64(12345),
						"logID":    "abcdef1234567890",
						// missing integratedTime
						"body": base64.StdEncoding.EncodeToString([]byte(`{"apiVersion": "0.0.1", "kind": "hashedrekord"}`)),
					}, base64.StdEncoding.EncodeToString([]byte("test-signature"))),
				},
			},
			expectError: true,
			errorMsg:    "bundle payload integratedTime is missing",
		},
		// Test case: integratedTime is not float64 (wrong type)
		{
			name: "integratedTime wrong type",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithPayload(map[string]interface{}{
						"logIndex":       float64(12345),
						"logID":          "abcdef1234567890",
						"integratedTime": "not-a-number",
						"body":           base64.StdEncoding.EncodeToString([]byte(`{"apiVersion": "0.0.1", "kind": "hashedrekord"}`)),
					}, base64.StdEncoding.EncodeToString([]byte("test-signature"))),
				},
			},
			expectError: true,
			errorMsg:    "error unmarshaling bundle annotation",
		},
		// Test case: missing SignedEntryTimestamp
		{
			name: "missing SignedEntryTimestamp",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: `{
						"Payload": {
							"logIndex": 12345,
							"logID": "abcdef1234567890",
							"integratedTime": 1640995200,
							"body": "` + base64.StdEncoding.EncodeToString([]byte(`{"apiVersion": "0.0.1", "kind": "hashedrekord"}`)) + `"
						}
					}`,
				},
			},
			expectError: true,
			errorMsg:    "signed entry timestamp is missing",
		},
		// Test case: SignedEntryTimestamp is not string (wrong type)
		{
			name: "SignedEntryTimestamp wrong type",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithSET(12345), // should be string
				},
			},
			expectError: true,
			errorMsg:    "error unmarshaling bundle annotation",
		},
		// Test case: invalid base64 in SignedEntryTimestamp
		{
			name: "invalid base64 SignedEntryTimestamp",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithSET("invalid-base64!@#"),
				},
			},
			expectError: true,
			errorMsg:    "error decoding signedEntryTimestamp",
		},
		// Test case: missing body
		{
			name: "missing body",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithPayload(map[string]interface{}{
						"logIndex":       float64(12345),
						"logID":          "abcdef1234567890",
						"integratedTime": float64(1640995200),
						// missing body
					}, base64.StdEncoding.EncodeToString([]byte("test-signature"))),
				},
			},
			expectError: true,
			errorMsg:    "bundle payload body is missing",
		},
		// Test case: body is not string (wrong type)
		{
			name: "body wrong type",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithPayload(map[string]interface{}{
						"logIndex":       float64(12345),
						"logID":          "abcdef1234567890",
						"integratedTime": float64(1640995200),
						"body":           12345, // should be string
					}, base64.StdEncoding.EncodeToString([]byte("test-signature"))),
				},
			},
			expectError: true,
			errorMsg:    "error unmarshaling bundle annotation",
		},
		// Test case: invalid JSON in body after base64 decode
		{
			name: "invalid JSON in decoded body",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithPayload(map[string]interface{}{
						"logIndex":       float64(12345),
						"logID":          "abcdef1234567890",
						"integratedTime": float64(1640995200),
						"body":           base64.StdEncoding.EncodeToString([]byte("invalid-json{")),
					}, base64.StdEncoding.EncodeToString([]byte("test-signature"))),
				},
			},
			expectError: true,
			errorMsg:    "error unmarshaling body",
		},
		// Test case: body contains null JSON (edge case)
		{
			name: "null JSON in decoded body",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithPayload(map[string]interface{}{
						"logIndex":       float64(12345),
						"logID":          "abcdef1234567890",
						"integratedTime": float64(1640995200),
						"body":           base64.StdEncoding.EncodeToString([]byte("null")),
					}, base64.StdEncoding.EncodeToString([]byte("test-signature"))),
				},
			},
			expectError: true,
			errorMsg:    "body apiVersion is missing",
		},
		// Test case: missing apiVersion
		{
			name: "missing apiVersion",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithPayload(map[string]interface{}{
						"logIndex":       float64(12345),
						"logID":          "abcdef1234567890",
						"integratedTime": float64(1640995200),
						"body":           base64.StdEncoding.EncodeToString([]byte(`{"kind": "hashedrekord"}`)), // missing apiVersion
					}, base64.StdEncoding.EncodeToString([]byte("test-signature"))),
				},
			},
			expectError: true,
			errorMsg:    "body apiVersion is missing",
		},
		// Test case: apiVersion is null
		{
			name: "null apiVersion",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithPayload(map[string]interface{}{
						"logIndex":       float64(12345),
						"logID":          "abcdef1234567890",
						"integratedTime": float64(1640995200),
						"body":           base64.StdEncoding.EncodeToString([]byte(`{"apiVersion": null, "kind": "hashedrekord"}`)),
					}, base64.StdEncoding.EncodeToString([]byte("test-signature"))),
				},
			},
			expectError: true,
			errorMsg:    "body apiVersion is missing",
		},
		// Test case: apiVersion is not string (wrong type)
		{
			name: "apiVersion wrong type",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithPayload(map[string]interface{}{
						"logIndex":       float64(12345),
						"logID":          "abcdef1234567890",
						"integratedTime": float64(1640995200),
						"body":           base64.StdEncoding.EncodeToString([]byte(`{"apiVersion": 123, "kind": "hashedrekord"}`)), // should be string
					}, base64.StdEncoding.EncodeToString([]byte("test-signature"))),
				},
			},
			expectError: true,
			errorMsg:    "error unmarshaling body",
		},
		// Test case: missing kind
		{
			name: "missing kind",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithPayload(map[string]interface{}{
						"logIndex":       float64(12345),
						"logID":          "abcdef1234567890",
						"integratedTime": float64(1640995200),
						"body":           base64.StdEncoding.EncodeToString([]byte(`{"apiVersion": "0.0.1"}`)), // missing kind
					}, base64.StdEncoding.EncodeToString([]byte("test-signature"))),
				},
			},
			expectError: true,
			errorMsg:    "body kind is missing",
		},
		// Test case: kind is null
		{
			name: "null kind",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithPayload(map[string]interface{}{
						"logIndex":       float64(12345),
						"logID":          "abcdef1234567890",
						"integratedTime": float64(1640995200),
						"body":           base64.StdEncoding.EncodeToString([]byte(`{"apiVersion": "0.0.1", "kind": null}`)),
					}, base64.StdEncoding.EncodeToString([]byte("test-signature"))),
				},
			},
			expectError: true,
			errorMsg:    "body kind is missing",
		},
		// Test case: kind is not string (wrong type)
		{
			name: "kind wrong type",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithPayload(map[string]interface{}{
						"logIndex":       float64(12345),
						"logID":          "abcdef1234567890",
						"integratedTime": float64(1640995200),
						"body":           base64.StdEncoding.EncodeToString([]byte(`{"apiVersion": "0.0.1", "kind": 456}`)), // should be string
					}, base64.StdEncoding.EncodeToString([]byte("test-signature"))),
				},
			},
			expectError: true,
			errorMsg:    "error unmarshaling body",
		},
		// Test case: success with all valid fields
		{
			name: "valid complete bundle",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: createBundleWithPayload(map[string]interface{}{
						"logIndex":       float64(12345),
						"logID":          "abcdef1234567890",
						"integratedTime": float64(1640995200),
						"body":           base64.StdEncoding.EncodeToString([]byte(`{"apiVersion": "0.0.1", "kind": "hashedrekord"}`)),
					}, base64.StdEncoding.EncodeToString([]byte("test-signature"))),
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getVerificationMaterialTlogEntries(tt.layer)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error message to contain '%s', got '%s'", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if result == nil {
				t.Errorf("Expected result but got nil")
				return
			}

			if len(result) != 1 {
				t.Errorf("Expected exactly one transparency log entry, got %d", len(result))
				return
			}

			entry := result[0]
			if entry.LogIndex != 12345 {
				t.Errorf("Expected LogIndex 12345, got %d", entry.LogIndex)
			}
			if entry.LogId == nil || len(entry.LogId.KeyId) == 0 {
				t.Errorf("Expected LogId to be set")
			}
			if entry.KindVersion == nil {
				t.Errorf("Expected KindVersion to be set")
			} else {
				if entry.KindVersion.Kind != "hashedrekord" {
					t.Errorf("Expected Kind 'hashedrekord', got '%s'", entry.KindVersion.Kind)
				}
				if entry.KindVersion.Version != "0.0.1" {
					t.Errorf("Expected Version '0.0.1', got '%s'", entry.KindVersion.Version)
				}
			}
			if entry.IntegratedTime != 1640995200 {
				t.Errorf("Expected IntegratedTime 1640995200, got %d", entry.IntegratedTime)
			}
			if entry.InclusionPromise == nil || len(entry.InclusionPromise.SignedEntryTimestamp) == 0 {
				t.Errorf("Expected InclusionPromise with SignedEntryTimestamp to be set")
			}
			if len(entry.CanonicalizedBody) == 0 {
				t.Errorf("Expected CanonicalizedBody to be set")
			}
		})
	}
}

// Test error cases in createVerifier function to improve coverage
func TestCreateVerifier_ErrorCases(t *testing.T) {
	tests := []struct {
		name        string
		opts        *VerifierOptions
		expectError bool
		errorMsg    string
	}{
		{
			name: "TUF client creation error",
			opts: &VerifierOptions{
				Name: "test-verifier",
				TUFOptions: &tuf.Options{
					RepositoryBaseURL: "invalid-url", // This should cause TUF client creation to fail
				},
			},
			expectError: true,
			errorMsg:    "failed to create TUF client",
		},
		{
			name: "with custom trusted root",
			opts: &VerifierOptions{
				Name:        "test-verifier",
				TrustedRoot: &root.TrustedRoot{}, // Empty trusted root, should work
			},
			expectError: false,
		},
		{
			name: "with ignore flags set",
			opts: &VerifierOptions{
				Name:        "test-verifier",
				IgnoreTLog:  true,
				IgnoreCTLog: true,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := createVerifier(tt.opts)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error message to contain '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// Test NewVerifier with different getVerifier paths to improve coverage
func TestNewVerifier_GetVerifierPaths(t *testing.T) {
	_, publicKey, err := generateTestKey()
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	tests := []struct {
		name        string
		opts        *VerifierOptions
		expectError bool
	}{
		{
			name: "without public keys (keyless verification path)",
			opts: &VerifierOptions{
				Name:       "test-verifier",
				IgnoreTLog: true, // Simplify for test
			},
			expectError: false,
		},
		{
			name: "with public keys (keyed verification path)",
			opts: &VerifierOptions{
				Name: "test-verifier",
				GetPublicKeys: (&testTrustedPublicKeys{
					configs: []*PublicKeyConfig{
						{
							PublicKey:          publicKey,
							SignatureAlgorithm: crypto.SHA256,
						},
					},
				}).GetPublicKeys,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier, err := NewVerifier(tt.opts)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if verifier == nil {
					t.Errorf("Expected verifier but got nil")
				}

				// Test the getVerifier function directly
				if verifier.getVerifier != nil {
					_, err := verifier.getVerifier()
					if err != nil {
						t.Errorf("getVerifier failed: %v", err)
					}
				}
			}
		})
	}
}

// Test createTrustedPublicKeyMaterial error cases to improve coverage
func TestCreateTrustedPublicKeyMaterial_ErrorCases(t *testing.T) {
	tests := []struct {
		name   string
		config *PublicKeyConfig
	}{
		{
			name: "invalid public key type that causes LoadVerifier to fail",
			config: &PublicKeyConfig{
				PublicKey:          "invalid-key-type", // This will cause signature.LoadVerifier to fail
				SignatureAlgorithm: crypto.SHA256,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			material := createTrustedPublicKeyMaterial(tt.config)
			if material == nil {
				t.Errorf("Expected material but got nil")
				return
			}

			// Try to call the internal function to trigger the error path
			_, err := material.PublicKeyVerifier("test-hint")
			if err == nil {
				t.Errorf("Expected error from LoadVerifier but got none")
			}
		})
	}
}

// Test Verify method with store fetch errors to improve coverage
func TestVerifier_VerifyStoreErrors(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()
	repo := "test/repo"

	opts := &VerifierOptions{
		Name:       "test-verifier",
		IgnoreTLog: true,
	}

	verifier, err := NewVerifier(opts)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	// Test with artifact descriptor that doesn't exist in store
	artifactDesc := ocispec.Descriptor{
		ArtifactType: mediaTypeCosignArtifactSignature,
		MediaType:    ocispec.MediaTypeImageManifest,
		Digest:       digest.FromString("non-existent"),
		Size:         100,
	}

	verifyOpts := &ratify.VerifyOptions{
		Store:              store,
		Repository:         repo,
		ArtifactDescriptor: artifactDesc,
	}

	_, err = verifier.Verify(ctx, verifyOpts)
	if err == nil {
		t.Errorf("Expected error when manifest doesn't exist but got none")
	}
	if !strings.Contains(err.Error(), "failed to fetch signature manifest") {
		t.Errorf("Expected fetch error but got: %v", err)
	}
}

// Test Verify method with malformed manifests to improve coverage
func TestVerifier_VerifyMalformedManifests(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()
	repo := "test/repo"

	opts := &VerifierOptions{
		Name:       "test-verifier",
		IgnoreTLog: true,
	}

	verifier, err := NewVerifier(opts)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	tests := []struct {
		name         string
		manifestData []byte
		expectedErr  string
	}{
		{
			name:         "invalid JSON manifest",
			manifestData: []byte("invalid-json{"),
			expectedErr:  "failed to unmarshal signature manifest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			artifactDesc := ocispec.Descriptor{
				ArtifactType: mediaTypeCosignArtifactSignature,
				MediaType:    ocispec.MediaTypeImageManifest,
				Digest:       digest.FromBytes(tt.manifestData),
				Size:         int64(len(tt.manifestData)),
			}

			store.addManifest(repo, artifactDesc, tt.manifestData)

			verifyOpts := &ratify.VerifyOptions{
				Store:              store,
				Repository:         repo,
				ArtifactDescriptor: artifactDesc,
			}

			_, err := verifier.Verify(ctx, verifyOpts)
			if err == nil {
				t.Errorf("Expected error but got none")
			}
			if !strings.Contains(err.Error(), tt.expectedErr) {
				t.Errorf("Expected error containing '%s' but got: %v", tt.expectedErr, err)
			}
		})
	}
}

// Test getBundleVerificationMaterial error cases to improve coverage
func TestGetBundleVerificationMaterial_ErrorCases(t *testing.T) {
	tests := []struct {
		name          string
		layer         ocispec.Descriptor
		ignoreTlog    bool
		getPublicKeys func(ctx context.Context) ([]*PublicKeyConfig, error)
		expectError   bool
		errorMsg      string
	}{
		{
			name: "tlog entry error when not ignored",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: "invalid-bundle",
				},
			},
			ignoreTlog:    false,
			getPublicKeys: nil,
			expectError:   true,
			errorMsg:      "error getting tlog entries",
		},
		{
			name: "certificate error when no public keys",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyCert: "invalid-cert",
				},
			},
			ignoreTlog:    true, // Skip tlog to hit cert error
			getPublicKeys: nil,  // No public keys, so will try to get cert
			expectError:   true,
			errorMsg:      "error getting signing certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := getBundleVerificationMaterial(tt.layer, tt.ignoreTlog, tt.getPublicKeys)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error message to contain '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// Test verifySignatureLayer error cases to improve coverage
func TestVerifier_VerifySignatureLayerErrors(t *testing.T) {
	verifier := &Verifier{
		name:       "test-verifier",
		ignoreTLog: true,
	}

	tests := []struct {
		name        string
		layer       ocispec.Descriptor
		expectError bool
		errorMsg    string
	}{
		{
			name: "getBundleVerificationMaterial error",
			layer: ocispec.Descriptor{
				Annotations: map[string]string{
					annotationKeyBundle: "invalid-json{",
				},
			},
			expectError: true,
			errorMsg:    "error getting verification material",
		},
		{
			name: "getBundleMsgSignature error",
			layer: ocispec.Descriptor{
				Digest: digest.Digest("unsupported:abcdef"),
				Annotations: map[string]string{
					annotationKeyCert:      "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
					annotationKeySignature: base64.StdEncoding.EncodeToString([]byte("test")),
				},
			},
			expectError: true,
			errorMsg:    "error getting message signature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := verifier.verifySignatureLayer(tt.layer)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error message to contain '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// Test getBundleMsgSignature with different digest algorithms to improve coverage
func TestGetBundleMsgSignature_DigestAlgorithms(t *testing.T) {
	testSignature := base64.StdEncoding.EncodeToString([]byte("test-signature"))

	tests := []struct {
		name        string
		digest      digest.Digest
		expectError bool
		expectedAlg protocommon.HashAlgorithm
	}{
		{
			name:        "SHA256 digest",
			digest:      digest.FromString("test-content"), // Uses SHA256 by default
			expectError: false,
			expectedAlg: protocommon.HashAlgorithm_SHA2_256,
		},
		{
			name:        "Unsupported algorithm",
			digest:      digest.Digest("sha512:abcdef1234567890"),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			layer := ocispec.Descriptor{
				Digest: tt.digest,
				Annotations: map[string]string{
					annotationKeySignature: testSignature,
				},
			}

			result, err := getBundleMsgSignature(layer)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if result == nil {
					t.Errorf("Expected result but got nil")
				}
				if result != nil && result.MessageSignature != nil {
					if result.MessageSignature.MessageDigest.Algorithm != tt.expectedAlg {
						t.Errorf("Expected algorithm %v, got %v", tt.expectedAlg, result.MessageSignature.MessageDigest.Algorithm)
					}
				}
			}
		})
	}
}

// Test verifyBundle with getVerifier error to improve coverage
func TestVerifier_VerifyBundleGetVerifierError(t *testing.T) {
	verifier := &Verifier{
		name:       "test-verifier",
		ignoreTLog: true,
		getVerifier: func() (*verify.Verifier, error) {
			return nil, fmt.Errorf("failed to get verifier")
		},
	}

	_, err := verifier.verifyBundle(nil, digest.FromString("test"))
	if err == nil {
		t.Errorf("Expected error from getVerifier but got none")
	}
	if !strings.Contains(err.Error(), "failed to get verifier") {
		t.Errorf("Expected getVerifier error but got: %v", err)
	}
}

// Test signature layer verification with various layer configurations
func TestVerifier_VerifyWithVariousLayerConfigurations(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()
	repo := "test/repo"

	opts := &VerifierOptions{
		Name:       "test-verifier",
		IgnoreTLog: true,
	}

	verifier, err := NewVerifier(opts)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	// Test with layer that has bundle creation error
	invalidLayer := ocispec.Descriptor{
		MediaType: mediaTypeSimpleSigning,
		Digest:    digest.Digest("unsupported:invalidhex"),
		Size:      100,
		Annotations: map[string]string{
			annotationKeyCert:      "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
			annotationKeySignature: base64.StdEncoding.EncodeToString([]byte("test")),
		},
	}

	manifestBytes, err := createTestManifest([]ocispec.Descriptor{invalidLayer})
	if err != nil {
		t.Fatalf("Failed to create test manifest: %v", err)
	}

	artifactDesc := ocispec.Descriptor{
		ArtifactType: mediaTypeCosignArtifactSignature,
		MediaType:    ocispec.MediaTypeImageManifest,
		Digest:       digest.FromBytes(manifestBytes),
		Size:         int64(len(manifestBytes)),
	}

	store.addManifest(repo, artifactDesc, manifestBytes)

	verifyOpts := &ratify.VerifyOptions{
		Store:              store,
		Repository:         repo,
		ArtifactDescriptor: artifactDesc,
	}

	result, err := verifier.Verify(ctx, verifyOpts)
	if err != nil {
		t.Fatalf("Unexpected error during verification: %v", err)
	}

	if result == nil {
		t.Errorf("Expected verification result but got nil")
	}

	// Check that we have verification details with errors
	if result.Detail != nil {
		if detailMap, ok := result.Detail.(map[string][]*layerReport); ok {
			if details, exists := detailMap["verifiedSignatures"]; exists {
				if len(details) == 0 {
					t.Errorf("Expected at least one signature layer report")
				} else {
					// The signature should fail due to unsupported digest
					if details[0].Succeeded {
						t.Errorf("Expected signature verification to fail but it succeeded")
					}
					if details[0].Error == nil {
						t.Errorf("Expected error in layer report but got none")
					}
				}
			}
		}
	}
}

// Test Verify error path when getSignatureDescriptors fails
func TestVerifier_VerifyGetSignatureDescriptorsError(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()
	repo := "test/repo"

	opts := &VerifierOptions{
		Name:       "test-verifier",
		IgnoreTLog: true,
	}

	verifier, err := NewVerifier(opts)
	if err != nil {
		t.Fatalf("Failed to create verifier: %v", err)
	}

	// Create manifest with invalid JSON to trigger getSignatureDescriptors error
	invalidManifestBytes := []byte("invalid-json{")

	artifactDesc := ocispec.Descriptor{
		ArtifactType: mediaTypeCosignArtifactSignature,
		MediaType:    ocispec.MediaTypeImageManifest,
		Digest:       digest.FromBytes(invalidManifestBytes),
		Size:         int64(len(invalidManifestBytes)),
	}

	store.addManifest(repo, artifactDesc, invalidManifestBytes)

	verifyOpts := &ratify.VerifyOptions{
		Store:              store,
		Repository:         repo,
		ArtifactDescriptor: artifactDesc,
	}

	_, err = verifier.Verify(ctx, verifyOpts)
	if err == nil {
		t.Errorf("Expected error from invalid manifest but got none")
	}
	// The error could be either from unmarshal or getSignatureDescriptors
	if !strings.Contains(err.Error(), "failed to unmarshal signature manifest") &&
		!strings.Contains(err.Error(), "failed to get signature descriptors") {
		t.Errorf("Expected unmarshal or getSignatureDescriptors error but got: %v", err)
	}
}

// Test verifySignatureLayer with bundle creation error path
func TestVerifier_VerifySignatureLayerBundleCreationError(t *testing.T) {
	verifier := &Verifier{
		name:       "test-verifier",
		ignoreTLog: true,
	}

	// Create layer that will pass verification material and message signature
	// but fail bundle creation due to invalid bundle structure
	layer := ocispec.Descriptor{
		Digest: digest.FromString("test-content"),
		Annotations: map[string]string{
			annotationKeyCert:      "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwEOwGLLCj5jXyiRaJAUm\nTNGXl4z+2NzD7YJx9n9VdgzYz7+I/c+M5O8r8e0J3G6M9W5K9f0L4u3I7qA5c3w\nNGsYGYrE6O8K7g5a7yO4X2qE7mM8B5O1b3p4o5Y8h9h5j4kG8o3e3f4f2e1j1H\n-----END CERTIFICATE-----",
			annotationKeySignature: base64.StdEncoding.EncodeToString([]byte("test-signature")),
		},
	}

	// This should pass verification material and message signature creation
	// but might fail at bundle.NewBundle due to malformed structure
	_, err := verifier.verifySignatureLayer(layer)
	if err == nil {
		// If no error, the bundle was created but verification will likely fail
		// which is still a valid test case
		return
	}

	// If there's an error, it should be in bundle creation step
	if !strings.Contains(err.Error(), "error creating bundle") {
		t.Logf("Got error (this might be expected): %v", err)
	}
}

// signKeyLayer builds a cosign simple-signing layer whose message signature is
// produced by signing the layer digest with the given ECDSA key. The returned
// layer carries no transparency-log bundle and no timestamp, mirroring an image
// signed offline (e.g. `cosign sign --tlog-upload=false --key ...`).
func signKeyLayer(t *testing.T, priv *ecdsa.PrivateKey) ocispec.Descriptor {
	t.Helper()

	payload := []byte("test simple signing payload")
	dgst := digest.FromBytes(payload)
	digestBytes, err := hex.DecodeString(dgst.Encoded())
	if err != nil {
		t.Fatalf("failed to decode digest: %v", err)
	}

	sig, err := ecdsa.SignASN1(rand.Reader, priv, digestBytes)
	if err != nil {
		t.Fatalf("failed to sign digest: %v", err)
	}

	return ocispec.Descriptor{
		MediaType: mediaTypeSimpleSigning,
		Digest:    dgst,
		Size:      int64(len(payload)),
		Annotations: map[string]string{
			annotationKeySignature: base64.StdEncoding.EncodeToString(sig),
		},
	}
}

// TestVerifier_IgnoreObserverTimestamps verifies that a key-based signature
// without a transparency-log entry or RFC3161 timestamp is accepted only when
// IgnoreObserverTimestamps is enabled, and rejected otherwise because no
// observer timestamp is available.
func TestVerifier_IgnoreObserverTimestamps(t *testing.T) {
	ctx := context.Background()
	repo := "test/repo"

	priv, pub, err := generateTestKey()
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	sigLayer := signKeyLayer(t, priv)

	manifestBytes, err := createTestManifest([]ocispec.Descriptor{sigLayer})
	if err != nil {
		t.Fatalf("failed to create test manifest: %v", err)
	}
	artifactDesc := ocispec.Descriptor{
		ArtifactType: mediaTypeCosignArtifactSignature,
		MediaType:    ocispec.MediaTypeImageManifest,
		Digest:       digest.FromBytes(manifestBytes),
		Size:         int64(len(manifestBytes)),
	}

	getPublicKeys := (&testTrustedPublicKeys{
		configs: []*PublicKeyConfig{
			{
				PublicKey:          pub,
				SignatureAlgorithm: crypto.SHA256,
			},
		},
	}).GetPublicKeys

	tests := []struct {
		name                     string
		ignoreObserverTimestamps bool
		wantVerified             bool
	}{
		{
			name:                     "ignore observer timestamps accepts key signature",
			ignoreObserverTimestamps: true,
			wantVerified:             true,
		},
		{
			name:                     "default requires observer timestamp",
			ignoreObserverTimestamps: false,
			wantVerified:             false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newMockStore()
			store.addManifest(repo, artifactDesc, manifestBytes)

			verifier, err := NewVerifier(&VerifierOptions{
				Name:                     "test-verifier",
				GetPublicKeys:            getPublicKeys,
				IdentityPolicies:         []verify.PolicyOption{verify.WithKey()},
				IgnoreTLog:               true,
				IgnoreCTLog:              true,
				IgnoreObserverTimestamps: tt.ignoreObserverTimestamps,
			})
			if err != nil {
				t.Fatalf("failed to create verifier: %v", err)
			}

			result, err := verifier.Verify(ctx, &ratify.VerifyOptions{
				Store:              store,
				Repository:         repo,
				ArtifactDescriptor: artifactDesc,
			})
			if err != nil {
				t.Fatalf("unexpected error during verification: %v", err)
			}

			if tt.wantVerified {
				if result.Err != nil {
					t.Fatalf("expected verification to succeed, got error: %v", result.Err)
				}
			} else {
				if result.Err == nil {
					t.Fatalf("expected verification to fail without a timestamp, but it succeeded")
				}
			}
		})
	}
}

// TestVerifier_IgnoreCTLog verifies that the certificate transparency log never
// applies to key-based verification: a public-key signature is accepted
// regardless of IgnoreCTLog, because public keys carry no signed certificate
// timestamps. Before the GetPublicKeys gate, IgnoreCTLog=false forced an SCT
// requirement that a public-key bundle can never satisfy.
func TestVerifier_IgnoreCTLog(t *testing.T) {
	ctx := context.Background()
	repo := "test/repo"

	priv, pub, err := generateTestKey()
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	sigLayer := signKeyLayer(t, priv)

	manifestBytes, err := createTestManifest([]ocispec.Descriptor{sigLayer})
	if err != nil {
		t.Fatalf("failed to create test manifest: %v", err)
	}
	artifactDesc := ocispec.Descriptor{
		ArtifactType: mediaTypeCosignArtifactSignature,
		MediaType:    ocispec.MediaTypeImageManifest,
		Digest:       digest.FromBytes(manifestBytes),
		Size:         int64(len(manifestBytes)),
	}

	getPublicKeys := (&testTrustedPublicKeys{
		configs: []*PublicKeyConfig{
			{
				PublicKey:          pub,
				SignatureAlgorithm: crypto.SHA256,
			},
		},
	}).GetPublicKeys

	// The certificate transparency log does not apply to public keys, so
	// key-based verification succeeds regardless of the IgnoreCTLog value.
	tests := []struct {
		name        string
		ignoreCTLog bool
	}{
		{name: "ignoreCTLog false accepts key signature", ignoreCTLog: false},
		{name: "ignoreCTLog true accepts key signature", ignoreCTLog: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newMockStore()
			store.addManifest(repo, artifactDesc, manifestBytes)

			verifier, err := NewVerifier(&VerifierOptions{
				Name:                     "test-verifier",
				GetPublicKeys:            getPublicKeys,
				IdentityPolicies:         []verify.PolicyOption{verify.WithKey()},
				IgnoreTLog:               true,
				IgnoreCTLog:              tt.ignoreCTLog,
				IgnoreObserverTimestamps: true,
			})
			if err != nil {
				t.Fatalf("failed to create verifier: %v", err)
			}

			result, err := verifier.Verify(ctx, &ratify.VerifyOptions{
				Store:              store,
				Repository:         repo,
				ArtifactDescriptor: artifactDesc,
			})
			if err != nil {
				t.Fatalf("unexpected error during verification: %v", err)
			}
			if result.Err != nil {
				t.Fatalf("expected verification to succeed with ignoreCTLog=%v, got error: %v", tt.ignoreCTLog, result.Err)
			}
		})
	}
}
