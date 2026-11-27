package integration

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// Docker creates a directory in place of a missing bind-mount source, so the container then fails to start.
func TestCompose_MountsOnlyFilesThatExist(t *testing.T) {
	compose, err := os.ReadFile("../../docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	mounts := regexp.MustCompile(`(?m)^\s*-\s+(\./[^:\s]+):`).FindAllStringSubmatch(string(compose), -1)
	if len(mounts) == 0 {
		t.Fatal("found no bind mounts to check")
	}
	for _, m := range mounts {
		if _, err := os.Stat(filepath.Join("../..", m[1])); err != nil {
			t.Errorf("docker-compose.yml mounts %s, which does not exist", m[1])
		}
	}
}
