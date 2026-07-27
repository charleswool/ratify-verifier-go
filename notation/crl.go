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
	"fmt"
	"net/http"
	"time"

	"github.com/notaryproject/notation-core-go/revocation"
	corecrl "github.com/notaryproject/notation-core-go/revocation/crl"
	"github.com/notaryproject/notation-core-go/revocation/purpose"
	"github.com/notaryproject/notation-go/dir"
	notationcrl "github.com/notaryproject/notation-go/verifier/crl"
)

// defaultCRLFetchTimeout bounds each CRL distribution-point fetch so a slow or
// unresponsive CRL server cannot block signature verification indefinitely.
const defaultCRLFetchTimeout = 10 * time.Second

// CRLOptions contains options for CRL revocation checking.
type CRLOptions struct {
	// CacheEnabled enables file-backed CRL caching using Notation's cache
	// directory. Optional.
	CacheEnabled bool

	// HTTPTimeout bounds each CRL distribution-point fetch. Optional. When zero
	// or negative, defaultCRLFetchTimeout is used.
	HTTPTimeout time.Duration
}

// crlHandler creates the CRL fetcher and revocation validators. Its dependency
// function fields default to the real notation-core-go constructors and can be
// overridden in tests to exercise error paths without package-level state.
type crlHandler struct {
	newHTTPFetcher func(*http.Client) (*corecrl.HTTPFetcher, error)
	newValidator   func(revocation.Options) (revocation.Validator, error)
	cacheRootPath  func() (string, error)
}

// newCRLHandler returns a crlHandler wired to the production constructors.
func newCRLHandler() *crlHandler {
	return &crlHandler{
		newHTTPFetcher: corecrl.NewHTTPFetcher,
		newValidator:   revocation.NewWithOptions,
		cacheRootPath:  func() (string, error) { return dir.CacheFS().SysPath(dir.PathCRLCache) },
	}
}

// revocationValidators builds the code signing and timestamping revocation
// validators backed by a CRL fetcher configured from opts.
func (h *crlHandler) revocationValidators(opts *CRLOptions) (codeSigning, timestamping revocation.Validator, err error) {
	fetcher, err := h.newFetcher(opts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CRL fetcher: %w", err)
	}

	codeSigning, err = h.newValidator(revocation.Options{
		CRLFetcher:       fetcher,
		CertChainPurpose: purpose.CodeSigning,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create code signing revocation validator: %w", err)
	}

	timestamping, err = h.newValidator(revocation.Options{
		CRLFetcher:       fetcher,
		CertChainPurpose: purpose.Timestamping,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create timestamping revocation validator: %w", err)
	}

	return codeSigning, timestamping, nil
}

// newFetcher creates an HTTP CRL fetcher with a bounded per-fetch timeout,
// optionally backed by Notation's on-disk CRL cache.
func (h *crlHandler) newFetcher(opts *CRLOptions) (corecrl.Fetcher, error) {
	fetcher, err := h.newHTTPFetcher(&http.Client{Timeout: resolveTimeout(opts.HTTPTimeout, defaultCRLFetchTimeout)})
	if err != nil {
		return nil, err
	}
	if !opts.CacheEnabled {
		return fetcher, nil
	}

	cacheRoot, err := h.cacheRootPath()
	if err != nil {
		return nil, err
	}
	cache, err := notationcrl.NewFileCache(cacheRoot)
	if err != nil {
		return nil, err
	}
	fetcher.Cache = cache
	return fetcher, nil
}
