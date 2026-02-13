package client

import (
	"context"
	"testing"

	"github.com/tonylturner/cipdip/internal/cip/spec"
)

func TestFileObjectRequestValidation(t *testing.T) {
	client := &ENIPClient{}

	if _, err := client.fileObjectRequest(spec.CIPServiceInitiateUpload, 0, nil); err == nil {
		t.Fatalf("expected error for instance 0")
	}

	req, err := client.fileObjectRequest(spec.CIPServiceInitiateUpload, 0x0001, []byte{0x01})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Service != spec.CIPServiceInitiateUpload {
		t.Fatalf("unexpected service: %v", req.Service)
	}
	if req.Path.Class != spec.CIPClassFileObject || req.Path.Instance != 0x0001 {
		t.Fatalf("unexpected path: %#v", req.Path)
	}
}

func TestFileObjectMethodsRejectInstanceZero(t *testing.T) {
	client := &ENIPClient{}
	ctx := context.Background()

	if _, err := client.FileInitiateUpload(ctx, 0, nil); err == nil {
		t.Fatalf("expected error for FileInitiateUpload instance 0")
	}
	if _, err := client.FileInitiateDownload(ctx, 0, nil); err == nil {
		t.Fatalf("expected error for FileInitiateDownload instance 0")
	}
	if _, err := client.FileInitiatePartialRead(ctx, 0, nil); err == nil {
		t.Fatalf("expected error for FileInitiatePartialRead instance 0")
	}
	if _, err := client.FileInitiatePartialWrite(ctx, 0, nil); err == nil {
		t.Fatalf("expected error for FileInitiatePartialWrite instance 0")
	}
	if _, err := client.FileUploadTransfer(ctx, 0, nil); err == nil {
		t.Fatalf("expected error for FileUploadTransfer instance 0")
	}
	if _, err := client.FileDownloadTransfer(ctx, 0, nil); err == nil {
		t.Fatalf("expected error for FileDownloadTransfer instance 0")
	}
	if _, err := client.FileClear(ctx, 0, nil); err == nil {
		t.Fatalf("expected error for FileClear instance 0")
	}
}

