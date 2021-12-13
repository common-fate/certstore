package certstore

import (
	"crypto"
	"crypto/x509"
	"errors"
)

var (
	// ErrUnsupportedHash is returned by Signer.Sign() when the provided hash
	// algorithm isn't supported.
	ErrUnsupportedHash = errors.New("unsupported hash algorithm")
)

const (
	// Require a hardware token when fetching identities (Darwin only).
	RequireToken = 1
)

// Open opens the system's certificate store.
func Open() (Store, error) {
	return openStore()
}

// CertificateFilter filters the query for certificates.
type CertificateFilter struct {
	SubjectStartsWith string
}

// Store represents the system's certificate store.
type Store interface {
	// Identities gets a list of identities from the store.
	Identities(flags int) ([]Identity, error)

	// Certificates gets a list of certificates from the store.
	// Note: this is currently only implemented on darwin. Other systems
	// will return an empty array.
	// If filter is not nil, the query will be filtered.
	Certificates(filter *CertificateFilter) ([]Certificate, error)

	// AddCertificate adds a certificate to the keychain.
	// Note: this is currently only implemented on darwin.
	// other systems will return an error.
	AddCertificate(cert *x509.Certificate) error

	// Import imports a PKCS#12 (PFX) blob containing a certificate and private
	// key.
	Import(data []byte, password string) error

	// Close closes the store.
	Close()
}

type Certificate interface {
	Get() (*x509.Certificate, error)
	Delete() error
}

// Identity is a X.509 certificate and its corresponding private key.
type Identity interface {
	// Certificate gets the identity's certificate.
	Certificate() (*x509.Certificate, error)

	// CertificateChain attempts to get the identity's full certificate chain.
	CertificateChain() ([]*x509.Certificate, error)

	// Signer gets a crypto.Signer that uses the identity's private key.
	Signer() (crypto.Signer, error)

	// Delete deletes this identity from the system.
	Delete() error

	// Close any manually managed memory held by the Identity.
	Close()
}
