// SPDX-License-Identifier: MPL-2.0

package stats

import (
	"sync"
	"testing"
	"time"
)

func TestCountersDoNotDoubleCount(t *testing.T) {
	inputs := []string{
		`{"stat":[{"name":"inbound>>>socks>>>traffic>>>downlink","value":"100"},{"name":"outbound>>>proxy>>>traffic>>>downlink","value":"100"},{"name":"outbound>>>direct>>>traffic>>>uplink","value":20}]}`,
		"name: \"inbound>>>socks>>>traffic>>>downlink\" value: 100\nname: \"outbound>>>proxy>>>traffic>>>downlink\" value: 100\nname: \"outbound>>>direct>>>traffic>>>uplink\" value: 20",
	}
	for _, input := range inputs {
		snap := &TrafficSnapshot{}
		parseStatsOutput(input, snap)
		if snap.DownlinkBytes != 100 || snap.UplinkBytes != 20 {
			t.Fatalf("incorrect totals: %+v", snap)
		}
	}
}
func TestConcurrentRestartAndSubscription(t *testing.T) {
	c := NewClient("", "")
	c.interval = time.Millisecond
	defer c.Stop()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 30; j++ {
				ch := c.Subscribe()
				c.Start()
				c.Latest()
				c.Stop()
				c.Unsubscribe(ch)
			}
		}()
	}
	wg.Wait()
	c.Start()
	ch := c.Subscribe()
	defer c.Unsubscribe(ch)
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("polling did not resume")
	}
	c.Stop()
}
