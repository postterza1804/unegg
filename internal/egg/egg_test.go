package egg

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sampleSimpleHex is the binary from the specification "Simple Archive" example.
const sampleSimpleHex = "" +
	"45 47 47 41 00 01 01 00 00 00 00 00 00 00 22 82 E2 08 " +
	"E3 90 85 0A 00 00 00 00 05 00 00 00 00 00 00 00 22 82 E2 08 " +
	"13 0C B5 02 00 00 05 00 00 00 05 00 00 00 86 A6 10 36 22 82 E2 08 " +
	"68 65 6C 6C 6F " +
	"22 82 E2 08"

func writeSampleEgg(t *testing.T, path string) {
	t.Helper()
	fields := strings.Fields(sampleSimpleHex)
	buf := make([]byte, len(fields))
	for i, f := range fields {
		b, err := hex.DecodeString(f)
		if err != nil {
			t.Fatalf("decode hex: %v", err)
		}
		buf[i] = b[0]
	}
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatalf("write sample: %v", err)
	}
}

func TestParseSimpleArchive(t *testing.T) {
	tmp := t.TempDir()
	eggPath := filepath.Join(tmp, "simple.egg")
	writeSampleEgg(t, eggPath)

	arc, err := Parse(eggPath)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if arc.Version != 0x0100 {
		t.Fatalf("version = %x, want 0x0100", arc.Version)
	}
	if arc.ProgramID != 1 {
		t.Fatalf("program id = %d, want 1", arc.ProgramID)
	}
	if len(arc.Files) != 1 {
		t.Fatalf("files len = %d, want 1", len(arc.Files))
	}
	f := arc.Files[0]
	if f.Size != 5 {
		t.Fatalf("file size = %d, want 5", f.Size)
	}
	if len(f.Blocks) != 1 {
		t.Fatalf("blocks len = %d, want 1", len(f.Blocks))
	}
	b := f.Blocks[0]
	if b.Method != 0 {
		t.Fatalf("block method = %d, want 0 (store)", b.Method)
	}
	if b.UnpackSize != 5 {
		t.Fatalf("block unpack = %d, want 5", b.UnpackSize)
	}
}

func TestExtractSimpleArchive(t *testing.T) {
	tmp := t.TempDir()
	eggPath := filepath.Join(tmp, "simple.egg")
	writeSampleEgg(t, eggPath)

	arc, err := Parse(eggPath)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	dest := filepath.Join(tmp, "out")
	if err := arc.ExtractAll(ExtractOptions{Dest: dest, Quiet: true, Concurrency: 2}); err != nil {
		t.Fatalf("extract: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dest, "00000000"))
	if err != nil {
		t.Fatalf("read extracted: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("extracted content = %q, want %q", data, "hello")
	}
}

func TestSecureJoin(t *testing.T) {
	base := t.TempDir()

	got, err := secureJoin(base, "nested/file.txt")
	if err != nil {
		t.Fatalf("secureJoin valid err: %v", err)
	}
	want := filepath.Join(base, "nested/file.txt")
	if got != want {
		t.Fatalf("secureJoin valid = %q, want %q", got, want)
	}

	if _, err := secureJoin(base, "/abs/path"); err == nil {
		t.Fatalf("secureJoin abs path should error")
	}
	if _, err := secureJoin(base, "../escape"); err == nil {
		t.Fatalf("secureJoin traversal should error")
	}
}
