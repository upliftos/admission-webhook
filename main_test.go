package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mkReq builds an admissionRequest for the given user, roleRef kind/name, and
// namespace (on the object). requestNS overrides request.namespace.
func mkReq(user, refKind, refName, objNS, requestNS string) *admissionRequest {
	r := &admissionRequest{UID: "uid-1", Namespace: requestNS}
	r.UserInfo.Username = user
	r.Object.Metadata.Namespace = objNS
	r.Object.RoleRef.Kind = refKind
	r.Object.RoleRef.Name = refName
	return r
}

func TestEvaluate_DeployerContainment(t *testing.T) {
	cases := []struct {
		name    string
		req     *admissionRequest
		allowed bool
	}{
		{
			name:    "app-manager into a upos-* namespace → allowed",
			req:     mkReq(deployerUser, "ClusterRole", appManagerRole, "upos-kiosk-prod", ""),
			allowed: true,
		},
		{
			name:    "app-manager into upliftos-system → allowed",
			req:     mkReq(deployerUser, "ClusterRole", appManagerRole, systemNS, ""),
			allowed: true,
		},
		{
			name:    "app-manager into kube-system → DENIED (the escalation)",
			req:     mkReq(deployerUser, "ClusterRole", appManagerRole, "kube-system", ""),
			allowed: false,
		},
		{
			name:    "app-manager into an arbitrary namespace → DENIED",
			req:     mkReq(deployerUser, "ClusterRole", appManagerRole, "default", ""),
			allowed: false,
		},
		{
			name:    "a DIFFERENT ClusterRole into upos-* → DENIED",
			req:     mkReq(deployerUser, "ClusterRole", "cluster-admin", "upos-kiosk-prod", ""),
			allowed: false,
		},
		{
			name:    "a namespaced Role (not ClusterRole) → DENIED",
			req:     mkReq(deployerUser, "Role", appManagerRole, "upos-kiosk-prod", ""),
			allowed: false,
		},
		{
			name:    "namespace comes from request.namespace when object has none → allowed",
			req:     mkReq(deployerUser, "ClusterRole", appManagerRole, "", "upos-kiosk-prod"),
			allowed: true,
		},
		{
			name:    "request.namespace=kube-system fallback → DENIED",
			req:     mkReq(deployerUser, "ClusterRole", appManagerRole, "", "kube-system"),
			allowed: false,
		},
		{
			name:    "a DIFFERENT principal binding into kube-system → allowed (not constrained)",
			req:     mkReq("system:serviceaccount:kube-system:some-controller", "ClusterRole", "cluster-admin", "kube-system", ""),
			allowed: true,
		},
		{
			name:    "a human admin binding anything → allowed (not constrained)",
			req:     mkReq("kubernetes-admin", "ClusterRole", "cluster-admin", "kube-system", ""),
			allowed: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, msg := evaluate(tc.req)
			if got != tc.allowed {
				t.Fatalf("evaluate allowed=%v, want %v (msg=%q)", got, tc.allowed, msg)
			}
			if !got && msg == "" {
				t.Fatalf("denied but no message")
			}
		})
	}
}

func TestHandleValidate_EchoesUIDAndDecision(t *testing.T) {
	review := admissionReview{
		APIVersion: "admission.k8s.io/v1",
		Kind:       "AdmissionReview",
		Request:    mkReq(deployerUser, "ClusterRole", appManagerRole, "kube-system", ""),
	}
	body, _ := json.Marshal(review)
	req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	handleValidate(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
	var out admissionReview
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.Response == nil {
		t.Fatal("nil response")
	}
	if out.Response.UID != "uid-1" {
		t.Fatalf("uid=%q, want uid-1 (must echo the request uid)", out.Response.UID)
	}
	if out.Response.Allowed {
		t.Fatal("kube-system bind should be DENIED")
	}
	if out.Response.Status == nil || out.Response.Status.Code != http.StatusForbidden {
		t.Fatalf("want 403 status on denial, got %+v", out.Response.Status)
	}
}

func TestHandleValidate_RejectsGarbage(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/validate", strings.NewReader("not json"))
	rec := httptest.NewRecorder()
	handleValidate(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400 on a non-AdmissionReview body", rec.Code)
	}
}

func TestGenerateCert_ProducesUsableServingMaterial(t *testing.T) {
	dir := t.TempDir()
	const dns = "upliftos-admission.upliftos-system.svc"
	if err := generateCert(dir, dns); err != nil {
		t.Fatalf("generateCert: %v", err)
	}
	for _, f := range []string{"tls.crt", "tls.key", "cabundle"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("missing %s: %v", f, err)
		}
	}
	// The cert+key must load as a TLS keypair (what the serve command does).
	if _, err := tls.LoadX509KeyPair(
		filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"),
	); err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}
	// cabundle must be non-empty base64 (it lands in the webhook config).
	cb, err := os.ReadFile(filepath.Join(dir, "cabundle"))
	if err != nil || len(cb) == 0 {
		t.Fatalf("cabundle unreadable/empty: %v", err)
	}
}
