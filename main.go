package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/digineo/go-ipset/v2"
	"github.com/ti-mo/netfilter"
)

type ipsetProps struct {
	name   string
	family netfilter.ProtoFamily
}

type ipsetCtx struct {
	// mu protects all properties below.
	mu *sync.Mutex

	nameToIpset    map[string]ipsetProps
	domainToIpsets map[string][]ipsetProps

	addedIPs map[[16]byte]struct{}

	ipv4Conn *ipset.Conn
	ipv6Conn *ipset.Conn
}

func (c *ipsetCtx) ipsets(names []string) (sets []ipsetProps, err error) {
	for _, name := range names {
		set, ok := c.nameToIpset[name]
		if ok {
			sets = append(sets, set)

			continue
		}

		set, err = c.ipsetProps(name)
		if err != nil {
			return nil, fmt.Errorf("querying ipset %q: %w", name, err)
		}

		c.nameToIpset[name] = set
		sets = append(sets, set)
	}

	return sets, nil
}

func (c *ipsetCtx) lookupHost(host string) (sets []ipsetProps) {
	// Search for matching ipset hosts starting with most specific
	// subdomain.  We could use a trie here but the simple, inefficient
	// solution isn't that expensive.  ~75 % for 10 subdomains vs 0, but
	// still sub-microsecond on a Core i7.
	//
	// TODO(a.garipov): Re-add benchmarks from the original PR.
	for i := 0; i != -1; i++ {
		host = host[i:]
		sets = c.domainToIpsets[host]
		if sets != nil {
			return sets
		}

		i = strings.Index(host, ".")
		if i == -1 {
			break
		}
	}

	// Check the root catch-all one.
	return c.domainToIpsets[""]
}

func (c *ipsetCtx) main() (err error) {
	counts := make(map[string]int)
	input := bufio.NewScanner(os.Stdin)

	fmt.Printf("输入 IP：\n")

	for input.Scan() {
		line := input.Text()

		if line == "bye" {
			break
		}
		counts[line]++

		var cfgStr string
		cfgStr = strings.TrimSpace(line)

		hostsAndNames := strings.Split(cfgStr, "/")

		hosts := strings.Split(hostsAndNames[0], ",")
		ipsetNames := strings.Split(hostsAndNames[1], ",")

		for i := range ipsetNames {
			ipsetNames[i] = strings.TrimSpace(ipsetNames[i])
		}

		for i := range hosts {
			hosts[i] = strings.TrimSpace(hosts[i])
		}

	}

	req := ctx.proxyCtx.Req
	host := req.Question[0].Name
	host = strings.TrimSuffix(host, ".")
	host = strings.ToLower(host)
	sets := c.lookupHost(host)

	entries := make([]*ipset.Entry, 0, len(counts))
	for _, ip := range counts {
		entries = append(entries, ipset.NewEntry(ipset.EntryIP(ip)))
	}

	for line, n := range counts {

		var ipsets []ipsetProps

		ipsets, err = c.ipsets(ipsetNames)

		var conn *ipset.Conn
		switch set.family {
		case netfilter.ProtoIPv4:
			conn = c.ipv4Conn
		case netfilter.ProtoIPv6:
			conn = c.ipv6Conn
		}

		fmt.Printf("%d : %s\n", n, line)
	}
}
