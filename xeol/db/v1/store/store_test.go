package store

import (
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/go-test/deep"
	v1 "github.com/noqcks/xeol/xeol/db/v1"
)

func assertIDReader(t *testing.T, reader v1.IDReader, expected v1.ID) {
	t.Helper()
	if actual, err := reader.GetID(); err != nil {
		t.Fatalf("failed to get ID: %+v", err)
	} else {
		diffs := deep.Equal(&expected, actual)
		if len(diffs) > 0 {
			for _, d := range diffs {
				t.Errorf("Diff: %+v", d)
			}
		}
	}
}

func TestStore_GetID_SetID(t *testing.T) {
	dbTempFile, err := ioutil.TempFile("", "grype-db-test-store")
	if err != nil {
		t.Fatalf("could not create temp file: %+v", err)
	}
	defer os.Remove(dbTempFile.Name())

	s, err := New(dbTempFile.Name(), true)
	if err != nil {
		t.Fatalf("could not create store: %+v", err)
	}

	expected := v1.ID{
		BuildTimestamp: time.Now().UTC(),
		SchemaVersion:  2,
	}

	if err = s.SetID(expected); err != nil {
		t.Fatalf("failed to set ID: %+v", err)
	}

	assertIDReader(t, s, expected)

}
