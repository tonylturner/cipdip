package pcap

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// CollectPcapFiles returns sorted PCAP/PCAPNG files under the root directory.
func CollectPcapFiles(root string) ([]string, error) {
	var pcaps []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".pcap" || ext == ".pcapng" {
			pcaps = append(pcaps, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk pcaps: %w", err)
	}
	sort.Strings(pcaps)
	return pcaps, nil
}
