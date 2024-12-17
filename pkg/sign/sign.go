package sign

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	fulcioapi "github.com/sigstore/fulcio/pkg/api"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	ssign "github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/util"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/sigstore/cosign/v2/pkg/cosign"
	rekor "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

func Bind() {

	var content ssign.Content

	data, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		log.Fatal(err)
	}

	content = &ssign.DSSEData{
		Data:        data,
		PayloadType: bundle.IntotoMediaType,
	}

	keypair, err := ssign.NewEphemeralKeypair(nil)
	if err != nil {
		log.Fatal(err)
	}
	publicKeyPem, err := keypair.GetPublicKeyPem()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Using public key:\n\n%s\n\n", publicKeyPem)

	opts := ssign.BundleOptions{}

	// Get trusted_root.json
	fetcher := fetcher.DefaultFetcher{}
	fetcher.SetHTTPUserAgent(util.ConstructUserAgent())

	tufOptions := &tuf.Options{
		Root:              tuf.StagingRoot(),
		RepositoryBaseURL: tuf.StagingMirror,
		Fetcher:           &fetcher,
	}
	tufClient, err := tuf.New(tufOptions)
	if err != nil {
		log.Fatal(err)
	}

	trustedRootJSON, err := tufClient.GetTarget("trusted_root.json")
	if err != nil {
		log.Fatal(err)
	}

	trustedRoot, err := root.NewTrustedRootFromJSON(trustedRootJSON)
	if err != nil {
		log.Fatal(err)
	}

	opts.TrustedRoot = trustedRoot

	if *idToken != "" {
		fulcioOpts := &ssign.FulcioOptions{
			BaseURL: "https://fulcio.sigstage.dev",
			Timeout: time.Duration(30 * time.Second),
			Retries: 1,
		}
		opts.CertificateProvider = ssign.NewFulcio(fulcioOpts)
		opts.CertificateProviderOptions = &ssign.CertificateProviderOptions{
			IDToken: *idToken,
		}
	}

	// Add timestamp
	tsaOpts := &ssign.TimestampAuthorityOptions{
		URL:     "https://timestamp.githubapp.com/api/v1/timestamp",
		Timeout: time.Duration(30 * time.Second),
		Retries: 1,
	}
	opts.TimestampAuthorities = append(opts.TimestampAuthorities, ssign.NewTimestampAuthority(tsaOpts))

	// staging TUF repo doesn't have accessible timestamp authorities
	opts.TrustedRoot = nil

	/// Add signature transaction to rekor
	rekorOpts := &ssign.RekorOptions{
		// BaseURL: "https://rekor.sigstage.dev",
		BaseURL: "https://rekor.sigstore.dev",
		Timeout: time.Duration(90 * time.Second),
		Retries: 1,
	}
	opts.TransparencyLogs = append(opts.TransparencyLogs, ssign.NewRekor(rekorOpts))

	bundle, err := ssign.Bundle(content, keypair, opts)
	if err != nil {
		log.Fatal(err)
	}

	bundleJSON, err := protojson.Marshal(bundle)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(bundleJSON))
}

func getOIDCToken() (*oauthflow.Token, error) {
	issuerURL := "https://oauth2.sigstore.dev/auth"
	tok, err := oauthflow.OIDConnect(
		issuerURL, // issuer
		"sigstore",
		"",                                 // FIXME: oidc.ClientSecre
		"http://localhost:0/auth/callback", // oidc.RedirectURL, // http://localhost:0/auth/callback
		oauthflow.NewClientCredentialsFlow(issuerURL),
	)
	if err != nil {
		return nil, err
	}
	return tok, nil
}

// internal/git

type CertSignerVerifier struct {
	signature.SignerVerifier

	Cert  []byte
	Chain []byte
}

func sign() (any, error) {
	ctx := context.Background()

	var privateKey crypto.PrivateKey
	var cert, certChain []byte

	sv, err := signature.LoadSignerVerifier(privateKey, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("error creating SignerVerifier: %w", err)
	}

	csv := &CertSignerVerifier{
		SignerVerifier: sv,
		Cert:           cert,
		Chain:          certChain,
	}

	commitSig, err := sv.SignMessage(bytes.NewBufferString("cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"))
	if err != nil {
		return nil, fmt.Errorf("error signing commit hash: %w", err)
	}

	// Publish entry to rekor
	entry, err := WriteTlog(ctx, []byte("cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"), commitSig, resp.Cert)
	if err != nil {
		return nil, fmt.Errorf("error uploading tlog (commit): %w", err)
	}

}

// WriteTlogWrites to rekor
func WriteTlog(ctx context.Context, message, signature []byte, cert *x509.Certificate) (*models.LogEntryAnon, error) {
	// Marshall the cert
	pem, err := cryptoutils.MarshalCertificateToPEM(cert)
	if err != nil {
		return nil, err
	}

	// cimpute the messagechecksum
	checkSum := sha256.New()
	if _, err := checkSum.Write(message); err != nil {
		return nil, err
	}

	// client, err := rekor.NewClient("")
	client, err := rekor.GetRekorClient("https://rekor.sigstore.dev", o.clientOpts...)
	if err != nil {
		return nil, err
	}

	return cosign.TLogUpload(ctx, client, signature, checkSum, pem)
}

// Extract the certificate
func GetCert(priv crypto.Signer) (*fulcioapi.CertificateResponse, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return nil, err
	}

	tok, err := oauthflow.OIDConnect(
		c.oidc.Issuer, c.oidc.ClientID, c.oidc.ClientSecret, c.oidc.RedirectURL, c.oidc.TokenGetter,
	)
	if err != nil {
		return nil, err
	}

	// Sign the email address as part of the request
	h := sha256.Sum256([]byte(tok.Subject))
	proof, err := priv.Sign(rand.Reader, h[:], nil)
	if err != nil {
		return nil, err
	}

	cr := fulcioapi.CertificateRequest{
		PublicKey: fulcioapi.Key{
			Algorithm: keyAlgorithm(priv),
			Content:   pubBytes,
		},
		SignedEmailAddress: proof,
	}

	return c.SigningCert(cr, tok.RawString)
}
