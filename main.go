// Package main — upliftos-admission.
//
// The §3.4.1 admission-webhook fallback (docs/specs/PRIVATE-CLOUD-2026-08-12.md).
// On a Kubernetes 1.28–1.29 cluster — below the 1.30 ValidatingAdmissionPolicy
// GA floor — this in-cluster validating webhook enforces the IDENTICAL
// containment the VAP would: the `upliftos-deployer` ServiceAccount may create a
// RoleBinding only when it binds the `upliftos-app-manager` ClusterRole into
// `upliftos-system` or a `upos-*` namespace. Anything else — most importantly
// binding app-manager into `kube-system` to read every namespace's Secrets — is
// DENIED. This is the escalation vanilla RBAC leaves open (spec §3.4).
//
// Two subcommands, one static binary:
//
//	serve   — the HTTPS webhook: POST /validate (AdmissionReview v1) + /healthz.
//	          Makes NO Kubernetes API calls; it only answers admission requests
//	          the apiserver sends it.
//	certgen — mint a self-signed serving cert (+ base64 caBundle) into a shared
//	          volume for the bootstrap Job's kubectl step to install. Keeps this
//	          binary dependency-free: cert material via crypto/x509, the Secret +
//	          webhook-config writes via kubectl (no client-go here).
//
// Design invariants:
//   - Stdlib only — no k8s.io/api, no client-go. The AdmissionReview shape is
//     stable for v1; we decode just the fields the predicate needs.
//   - The predicate is COMPILED IN, never read from a mutable ConfigMap.
//   - `evaluate` is pure and exhaustively unit-tested; it is the whole security
//     surface. Keep it byte-for-byte aligned with the VAP CEL in
//     bootstrap-manifest.ts.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// The ONLY principal this webhook constrains. Must match the SA the
	// bootstrap manifest creates + the VAP's matchConditions.
	deployerUser = "system:serviceaccount:upliftos-system:upliftos-deployer"
	// The ONLY ClusterRole the deployer may bind.
	appManagerRole = "upliftos-app-manager"
	// The ONLY namespaces the deployer may create RoleBindings in.
	systemNS    = "upliftos-system"
	appNSPrefix = "upos-"
)

// ── Minimal AdmissionReview v1 shapes (decode only what the predicate needs) ──

type admissionReview struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Request    *admissionRequest  `json:"request,omitempty"`
	Response   *admissionResponse `json:"response,omitempty"`
}

type admissionRequest struct {
	UID string `json:"uid"`
	// The namespace the request targets — the fallback when the object itself
	// carries no metadata.namespace (some CREATE paths).
	Namespace string      `json:"namespace"`
	UserInfo  userInfo    `json:"userInfo"`
	Object    roleBinding `json:"object"`
}

type userInfo struct {
	Username string `json:"username"`
}

type roleBinding struct {
	Metadata struct {
		Namespace string `json:"namespace"`
	} `json:"metadata"`
	RoleRef struct {
		APIGroup string `json:"apiGroup"`
		Kind     string `json:"kind"`
		Name     string `json:"name"`
	} `json:"roleRef"`
}

type admissionResponse struct {
	UID     string  `json:"uid"`
	Allowed bool    `json:"allowed"`
	Status  *status `json:"status,omitempty"`
}

type status struct {
	Code    int32  `json:"code"`
	Message string `json:"message"`
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: upliftos-admission <serve|certgen> [flags]")
	}
	switch os.Args[1] {
	case "serve":
		serveCmd(os.Args[2:])
	case "certgen":
		certgenCmd(os.Args[2:])
	default:
		log.Fatalf("unknown subcommand %q (want serve|certgen)", os.Args[1])
	}
}

// ── serve ────────────────────────────────────────────────────────────────────

func serveCmd(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":8443", "listen address")
	certFile := fs.String("tls-cert", "/tls/tls.crt", "serving certificate (PEM)")
	keyFile := fs.String("tls-key", "/tls/tls.key", "serving private key (PEM)")
	_ = fs.Parse(args)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/validate", handleValidate)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("upliftos-admission serving on %s", *addr)
	if err := srv.ListenAndServeTLS(*certFile, *keyFile); err != nil {
		log.Fatalf("server: %v", err)
	}
}

func handleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var review admissionReview
	if err := json.NewDecoder(r.Body).Decode(&review); err != nil || review.Request == nil {
		http.Error(w, "bad AdmissionReview", http.StatusBadRequest)
		return
	}
	allowed, msg := evaluate(review.Request)
	resp := admissionReview{
		APIVersion: "admission.k8s.io/v1",
		Kind:       "AdmissionReview",
		Response: &admissionResponse{
			UID:     review.Request.UID,
			Allowed: allowed,
		},
	}
	if !allowed {
		resp.Response.Status = &status{Code: http.StatusForbidden, Message: msg}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// evaluate is the whole security surface. It returns (allowed, denyMessage) and
// mirrors the VAP validations in bootstrap-manifest.ts EXACTLY. Only the
// deployer SA is constrained; every other principal's RoleBindings pass through
// (defense in depth — the webhook's matchConditions already pre-filter to the
// deployer, but if that feature gate is off the webhook still contains it here).
func evaluate(req *admissionRequest) (bool, string) {
	if req.UserInfo.Username != deployerUser {
		return true, ""
	}
	if req.Object.RoleRef.Kind != "ClusterRole" || req.Object.RoleRef.Name != appManagerRole {
		return false, "upliftos-deployer may only bind the upliftos-app-manager ClusterRole"
	}
	ns := req.Object.Metadata.Namespace
	if ns == "" {
		ns = req.Namespace
	}
	if ns != systemNS && !strings.HasPrefix(ns, appNSPrefix) {
		return false, "upliftos-deployer may only create RoleBindings in upliftos-system or upos-* namespaces"
	}
	return true, ""
}

// ── certgen ───────────────────────────────────────────────────────────────────

func certgenCmd(args []string) {
	fs := flag.NewFlagSet("certgen", flag.ExitOnError)
	outDir := fs.String("out-dir", "/work", "output directory for tls.crt / tls.key / cabundle")
	dns := fs.String("dns", "", "primary DNS SAN, e.g. upliftos-admission.upliftos-system.svc")
	_ = fs.Parse(args)
	if *dns == "" {
		log.Fatal("certgen: --dns is required")
	}
	if err := generateCert(*outDir, *dns); err != nil {
		log.Fatalf("certgen: %v", err)
	}
	log.Printf("certgen: wrote tls.crt, tls.key, cabundle to %s (SAN %s)", *outDir, *dns)
}

// generateCert writes a self-signed serving certificate (its own CA, valid 10y)
// plus a base64-encoded caBundle into outDir. Self-signed is deliberate: we do
// not manage the customer's cluster, so a long-lived cert scoped to this one
// webhook beats a rotation treadmill we cannot drive. Factored out for testing.
func generateCert(outDir, dns string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("serial: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: dns},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{dns, dns + ".cluster.local"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}
	crtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "tls.crt"), crtPEM, 0o644); err != nil {
		return fmt.Errorf("write tls.crt: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "tls.key"), keyPEM, 0o640); err != nil {
		return fmt.Errorf("write tls.key: %w", err)
	}
	cabundle := base64.StdEncoding.EncodeToString(crtPEM)
	if err := os.WriteFile(filepath.Join(outDir, "cabundle"), []byte(cabundle), 0o644); err != nil {
		return fmt.Errorf("write cabundle: %w", err)
	}
	return nil
}
