package engine

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ContentChunk represents a scannable piece of content extracted from a file
// or from within an archive.
type ContentChunk struct {
	Content  string
	FilePath string // virtual path (e.g., "archive.zip:inner/secret.env")
	Size     int64
}

// Size limits for archive extraction.
const (
	maxInnerFileSize    = 1 << 20       // 1 MB per inner file
	maxTotalExtractSize = 10 * (1 << 20) // 10 MB per archive
)

// ForceSkipBinaries tells the scanner to skip files that look like binaries.
// Uses the same heuristic as git: if the first 8KB contains a NUL byte, it's binary.
var ForceSkipBinaries = false

// archiveExtensions maps file extensions to their archive type.
var archiveExtensions = map[string]string{
	".zip": "zip",
	".jar": "zip",
	".war": "zip",
	".apk": "zip",
	".tar": "tar",
	".tgz": "targz",
	".gz":  "gz", // may be plain gz or tar.gz; resolved at runtime
}

// HandleFile reads a file and produces content chunks for scanning.
// Regular files produce one chunk. Archives produce one chunk per inner file.
func HandleFile(fpath string) ([]ContentChunk, error) {
	info, err := os.Stat(fpath)
	if err != nil {
		return nil, err
	}

	// Don't process extremely large files.
	if info.Size() > maxTotalExtractSize {
		return nil, nil
	}

	data, err := os.ReadFile(fpath)
	if err != nil {
		return nil, err
	}

	// Skip binary files if the flag is set. Same trick git uses:
	// if there's a NUL byte in the first 8KB, it's not a text file.
	if ForceSkipBinaries {
		sample := data
		if len(sample) > 8192 {
			sample = sample[:8192]
		}
		for _, b := range sample {
			if b == 0 {
				return nil, nil // skip binary file
			}
		}
	}

	ext := strings.ToLower(filepath.Ext(fpath))
	base := strings.ToLower(filepath.Base(fpath))

	// Detect .tar.gz / .tgz
	if strings.HasSuffix(base, ".tar.gz") || ext == ".tgz" {
		return handleTarGz(fpath, data)
	}

	if archiveType, ok := archiveExtensions[ext]; ok {
		switch archiveType {
		case "zip":
			return handleZip(fpath, data)
		case "tar":
			return handleTar(fpath, bytes.NewReader(data))
		case "gz":
			return handleGzip(fpath, data)
		}
	}

	// Default: regular file handler.
	return handleDefault(fpath, data)
}

// HandleArchive extracts files from an archive and returns content chunks.
func HandleArchive(fpath string, data []byte) ([]ContentChunk, error) {
	ext := strings.ToLower(filepath.Ext(fpath))
	base := strings.ToLower(filepath.Base(fpath))

	if strings.HasSuffix(base, ".tar.gz") || ext == ".tgz" {
		return handleTarGz(fpath, data)
	}

	switch ext {
	case ".zip", ".jar", ".war", ".apk":
		return handleZip(fpath, data)
	case ".tar":
		return handleTar(fpath, bytes.NewReader(data))
	case ".gz":
		return handleGzip(fpath, data)
	default:
		return handleDefault(fpath, data)
	}
}

// ---------------------------------------------------------------------------
// Handler 1: ZIP archives (.zip, .jar, .war, .apk)
// ---------------------------------------------------------------------------

func handleZip(archivePath string, data []byte) ([]ContentChunk, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}

	var chunks []ContentChunk
	var totalExtracted int64
	maxEntries := 10000
	entryCount := 0

	for _, f := range reader.File {
		entryCount++
		if entryCount > maxEntries {
			break
		}
		if f.FileInfo().IsDir() {
			continue
		}

		if strings.Contains(f.Name, "..") {
			continue
		}

		if f.UncompressedSize64 > maxInnerFileSize {
			continue
		}
		if totalExtracted+int64(f.UncompressedSize64) > maxTotalExtractSize {
			break
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}

		// Read with a size limit.
		buf, err := readLimited(rc, maxInnerFileSize)
		rc.Close()
		if err != nil {
			continue
		}

		if isBinary(buf) {
			continue
		}

		totalExtracted += int64(len(buf))
		virtualPath := archivePath + ":" + f.Name
		chunks = append(chunks, ContentChunk{
			Content:  string(buf),
			FilePath: virtualPath,
			Size:     int64(len(buf)),
		})
	}

	return chunks, nil
}

// ---------------------------------------------------------------------------
// Handler 2: TAR archives (.tar, .tar.gz, .tgz)
// ---------------------------------------------------------------------------

func handleTarGz(archivePath string, data []byte) ([]ContentChunk, error) {
	gzReader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gzReader.Close()

	return handleTar(archivePath, gzReader)
}

func handleTar(archivePath string, r io.Reader) ([]ContentChunk, error) {
	tr := tar.NewReader(r)

	var chunks []ContentChunk
	var totalExtracted int64
	maxEntries := 10000
	entryCount := 0

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		entryCount++
		if entryCount > maxEntries {
			break
		}

		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if strings.Contains(hdr.Name, "..") {
			continue
		}
		if hdr.Size > maxInnerFileSize {
			continue
		}
		if totalExtracted+hdr.Size > maxTotalExtractSize {
			break
		}

		buf, err := readLimited(tr, maxInnerFileSize)
		if err != nil {
			continue
		}

		if isBinary(buf) {
			continue
		}

		totalExtracted += int64(len(buf))
		virtualPath := archivePath + ":" + hdr.Name
		chunks = append(chunks, ContentChunk{
			Content:  string(buf),
			FilePath: virtualPath,
			Size:     int64(len(buf)),
		})
	}

	return chunks, nil
}

// ---------------------------------------------------------------------------
// Handler 3: Gzip files (.gz that aren't .tar.gz)
// ---------------------------------------------------------------------------

func handleGzip(fpath string, data []byte) ([]ContentChunk, error) {
	gzReader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gzReader.Close()

	buf, err := readLimited(gzReader, maxInnerFileSize)
	if err != nil {
		return nil, err
	}

	if isBinary(buf) {
		return nil, nil
	}

	// Use the gzip header name if available, otherwise strip .gz.
	innerName := gzReader.Name
	if innerName == "" {
		innerName = strings.TrimSuffix(filepath.Base(fpath), ".gz")
	}

	virtualPath := fpath + ":" + innerName
	return []ContentChunk{
		{Content: string(buf), FilePath: virtualPath, Size: int64(len(buf))},
	}, nil
}

// ---------------------------------------------------------------------------
// Handler 4: Default handler (regular files)
// ---------------------------------------------------------------------------

func handleDefault(fpath string, data []byte) ([]ContentChunk, error) {
	if isBinary(data) {
		return nil, nil
	}

	return []ContentChunk{
		{Content: string(data), FilePath: fpath, Size: int64(len(data))},
	}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// isBinary checks if data is likely binary by looking for null bytes in the
// first 512 bytes.
func isBinary(data []byte) bool {
	check := data
	if len(check) > 512 {
		check = check[:512]
	}
	return bytes.ContainsRune(check, 0)
}

// readLimited reads up to limit bytes from r.
func readLimited(r io.Reader, limit int64) ([]byte, error) {
	lr := io.LimitReader(r, limit+1)
	buf, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > limit {
		return nil, nil // exceeds limit; skip
	}
	return buf, nil
}

// IsArchiveFile returns true if the file extension indicates an archive format
// that HandleFile can process.
func IsArchiveFile(fpath string) bool {
	base := strings.ToLower(filepath.Base(fpath))
	if strings.HasSuffix(base, ".tar.gz") {
		return true
	}
	ext := strings.ToLower(filepath.Ext(fpath))
	_, ok := archiveExtensions[ext]
	return ok
}
