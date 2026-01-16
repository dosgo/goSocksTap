package iptools

import (
	"bufio"
	"net"
	"os"
	"strings"

	"github.com/yl2chen/cidranger"
)

type ChinaIPMatcher struct {
	ranger cidranger.Ranger
}

func NewChinaIPMatcher() *ChinaIPMatcher {
	return &ChinaIPMatcher{
		ranger: cidranger.NewPCTrieRanger(),
	}
}

// LoadFromFiles 加载下载好的中国 IP 段文件 (如 chnroute.txt)
func (m *ChinaIPMatcher) LoadFromFiles(v4File, v6File string) error {
	files := []string{v4File, v6File}
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			return err
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			_, network, err := net.ParseCIDR(line)
			if err == nil {
				m.ranger.Insert(cidranger.NewBasicRangerEntry(*network))
			}
		}
	}
	return nil
}

// IsChinaIP 判断 IP 是否属于中国
func (m *ChinaIPMatcher) IsChinaIP(ip net.IP) bool {
	contains, err := m.ranger.Contains(ip)
	if err != nil {
		return false
	}
	return contains
}
