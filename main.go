package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"errors"
	// "sync"
	"net"

	goipset "github.com/digineo/go-ipset/v2"
	"github.com/mdlayher/netlink"
	"github.com/ti-mo/netfilter"
)

var (
	c *goipset.Conn
)

func initLib() (err error) {
	c, err = goipset.Dial(netfilter.ProtoUnspec, &netlink.Config{})
	return
}

func addIP(ip net.IP, list string) error {
	p, err := c.Header(list)
	if err != nil {
		return err
	}
	var typeMatch bool
	if uint(p.Family.Value) == uint(netfilter.ProtoIPv4) {
		typeMatch = ip.To4() != nil
	} else if uint(p.Family.Value) == uint(netfilter.ProtoIPv6) {
		typeMatch = ip.To16() != nil
	}
	if !typeMatch {
		return errors.New("not matched type")
	}
	// AddIPCount.WithLabelValues(list).Add(1)
	return c.Add(list, goipset.NewEntry(goipset.EntryIP(ip)))
}

func flushSet(list string) error {
	return c.Flush(list)
}

func shutdownLib() error {
	return c.Close()
}

func main() {
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

		// err := initLib()
		// if err != nil {
		// 	return err
		// }
		for i := range hosts {
			for j := range ipsetNames {
				err := initLib()
				if err != nil {
				}
				err = flushSet(ipsetNames[j])
				// if err != nil {
				// 	fmt.Printf(string(err))
				// }

				err = addIP(net.ParseIP(hosts[i]), ipsetNames[j])
				// if err != nil {
				// 	fmt.Printf(string(err))
				// }
				err = shutdownLib()
				// if err != nil {
				// 	fmt.Printf(string(err))
				// }
			}
		}

	}


	for line, n := range counts {
		fmt.Printf("%d : %s\n", n, line)
	}
}