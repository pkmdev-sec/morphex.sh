package engine

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHandleRegularFile(t *testing.T) {
	dir := t.TempDir()
	fpath := filepath.Join(dir, "app.py")
	content := `API_KEY = "sk_live_abcdef1234567890abcdef12"` + "\n"
	if err := os.WriteFile(fpath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	chunks, err := HandleFile(fpath)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk, got %d", len(chunks))
	}
	if chunks[0].FilePath != fpath {
		t.Errorf("expected filepath %q, got %q", fpath, chunks[0].FilePath)
	}
	if chunks[0].Content != content {
		t.Errorf("expected content match, got %q", chunks[0].Content)
	}
}

func TestHandleZipArchive(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "secrets.zip")

	// Create a zip with two files inside.
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	secretContent := "DB_PASSWORD=super_secret_p4ssw0rd_1234\n"
	f, err := w.Create("config/secrets.env")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(secretContent)); err != nil {
		t.Fatal(err)
	}

	readmeContent := "# README\nThis is a readme.\n"
	f2, err := w.Create("README.md")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f2.Write([]byte(readmeContent)); err != nil {
		t.Fatal(err)
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(archivePath, buf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	chunks, err := HandleFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks from zip, got %d", len(chunks))
	}

	// Check virtual paths.
	foundSecret := false
	for _, c := range chunks {
		if strings.Contains(c.FilePath, ":config/secrets.env") {
			foundSecret = true
			if c.Content != secretContent {
				t.Errorf("secret file content mismatch: got %q", c.Content)
			}
		}
	}
	if !foundSecret {
		t.Error("expected to find config/secrets.env in zip chunks")
	}
}

func TestHandleTarGz(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "secrets.tar.gz")

	// Create a tar.gz with a secret file.
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)

	secretContent := "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
	hdr := &tar.Header{
		Name: "deploy/credentials.env",
		Mode: 0644,
		Size: int64(len(secretContent)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(secretContent)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	// Gzip the tar.
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	if _, err := gw.Write(tarBuf.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(archivePath, gzBuf.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}

	chunks, err := HandleFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk from tar.gz, got %d", len(chunks))
	}
	if !strings.Contains(chunks[0].FilePath, ":deploy/credentials.env") {
		t.Errorf("expected virtual path with deploy/credentials.env, got %q", chunks[0].FilePath)
	}
	if chunks[0].Content != secretContent {
		t.Errorf("content mismatch: got %q", chunks[0].Content)
	}
}

func TestHandleBinarySkip(t *testing.T) {
	dir := t.TempDir()
	fpath := filepath.Join(dir, "binary.dat")

	// Create a file with null bytes in the first 512 bytes.
	data := make([]byte, 1024)
	data[0] = 0x7f // ELF-like magic
	data[1] = 'E'
	data[2] = 'L'
	data[3] = 'F'
	data[100] = 0 // null byte

	if err := os.WriteFile(fpath, data, 0644); err != nil {
		t.Fatal(err)
	}

	chunks, err := HandleFile(fpath)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != 0 {
		t.Errorf("expected 0 chunks for binary file, got %d", len(chunks))
	}
}

func TestHandleZipSkipsBinary(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "mixed.zip")

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	// Add a text file.
	textContent := "SECRET_TOKEN=ghp_abcdef1234567890abcdef1234567890ab\n"
	f, _ := w.Create("config.env")
	f.Write([]byte(textContent))

	// Add a binary file (with null bytes).
	binData := make([]byte, 256)
	binData[10] = 0
	binData[20] = 0
	bf, _ := w.Create("program.bin")
	bf.Write(binData)

	w.Close()
	os.WriteFile(archivePath, buf.Bytes(), 0644)

	chunks, err := HandleFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk (binary skipped), got %d", len(chunks))
	}
	if !strings.Contains(chunks[0].FilePath, ":config.env") {
		t.Errorf("expected config.env chunk, got %q", chunks[0].FilePath)
	}
}

func TestScanFileDeep_Archive(t *testing.T) {
	dir := t.TempDir()
	archivePath := filepath.Join(dir, "app.zip")

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	// Create a file inside the zip that contains a real-looking secret.
	secretContent := `# Production config
STRIPE_SECRET_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
DATABASE_URL = "postgres://admin:very_secret_password_1234@db.prod.example.com:5432/myapp"
`
	f, _ := w.Create("config/production.env")
	f.Write([]byte(secretContent))
	w.Close()

	os.WriteFile(archivePath, buf.Bytes(), 0644)

	findings := ScanFileDeep(archivePath, 0.5)
	if len(findings) == 0 {
		t.Error("expected ScanFileDeep to find secrets inside zip archive")
	}

	// Check that findings reference the virtual path.
	for _, f := range findings {
		if !strings.Contains(f.File, ":config/production.env") {
			t.Errorf("expected finding to reference virtual path, got file=%q", f.File)
		}
		t.Logf("Found: file=%s line=%d detector=%s confidence=%.2f value=%s",
			f.File, f.Line, f.Detector, f.Confidence, f.MatchedValue)
	}
}

func TestIsArchiveFile(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"app.zip", true},
		{"lib.jar", true},
		{"deploy.war", true},
		{"app.apk", true},
		{"data.tar", true},
		{"data.tar.gz", true},
		{"data.tgz", true},
		{"data.gz", true},
		{"app.py", false},
		{"config.env", false},
		{"README.md", false},
	}

	for _, tc := range tests {
		got := IsArchiveFile(tc.path)
		if got != tc.want {
			t.Errorf("IsArchiveFile(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
