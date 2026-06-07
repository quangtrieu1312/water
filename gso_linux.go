package water

// gsoDevice wraps an IFF_VNET_HDR tun fd and presents the plain one-packet-per-call
// io.ReadWriteCloser that the rest of water (and its callers) expect. On Read it
// pulls one (possibly 64KB GSO) frame per syscall and splits it into MTU-sized IP
// packets, returning them one at a time from an internal buffer — so a single
// read() syscall yields a burst of packets that flow through the caller's pipeline
// back-to-back (amortizing per-packet handoff latency, the WireGuard-go technique).
// On Write it prepends a zero virtio_net_hdr (GSO_NONE, checksums already valid).

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
)

// gsoReadErrs counts (and rate-limits logging of) handleVirtioRead failures so a
// malformed/unsupported frame is skipped rather than tearing down the reader.
var gsoReadErrs atomic.Int64

const (
	// must exceed the largest single inner-MTU segment. Inner tun MTU is WAN-derived
	// and capped at the XDP-native virtio limit (3506); 4096 covers it with margin and
	// matches the caller's read buffer (src/main.go). 2048 panicked at the 3422 jumbo MTU.
	gsoSegBufSize  = 4096 // max single segment (IP+L4+payload)
	gsoMaxSegments = 128  // max segments per GSO super-frame
)

type gsoDevice struct {
	f *os.File

	readMu   sync.Mutex
	readBuff [virtioNetHdrLen + 65535]byte
	segBufs  [][]byte
	segSizes []int
	nSeg     int
	segIdx   int

	writePool sync.Pool
}

func newGSODevice(f *os.File) *gsoDevice {
	d := &gsoDevice{
		f:        f,
		segBufs:  make([][]byte, gsoMaxSegments),
		segSizes: make([]int, gsoMaxSegments),
	}
	for i := range d.segBufs {
		d.segBufs[i] = make([]byte, gsoSegBufSize)
	}
	d.writePool.New = func() any { b := make([]byte, virtioNetHdrLen+65535); return &b }
	return d
}

func (d *gsoDevice) Read(p []byte) (int, error) {
	d.readMu.Lock()
	defer d.readMu.Unlock()
	for {
		if d.segIdx < d.nSeg {
			n := copy(p, d.segBufs[d.segIdx][:d.segSizes[d.segIdx]])
			d.segIdx++
			return n, nil
		}
		n, err := d.f.Read(d.readBuff[:])
		if err != nil {
			return 0, err
		}
		nSeg, err := handleVirtioRead(d.readBuff[:n], d.segBufs, d.segSizes, 0)
		if err != nil {
			c := gsoReadErrs.Add(1)
			if c <= 20 {
				dump := d.readBuff[:min(n, 16)]
				fmt.Fprintf(os.Stderr, "[water-gso] split err #%d (n=%d hdr+ipver=% x): %v\n", c, n, dump, err)
			}
			continue // skip this frame; don't tear down the reader
		}
		d.nSeg = nSeg
		d.segIdx = 0
	}
}

func (d *gsoDevice) Write(p []byte) (int, error) {
	bp := d.writePool.Get().(*[]byte)
	buf := *bp
	for i := 0; i < virtioNetHdrLen; i++ {
		buf[i] = 0 // virtio_net_hdr: GSO_NONE, no NEEDS_CSUM
	}
	n := copy(buf[virtioNetHdrLen:], p)
	_, err := d.f.Write(buf[:virtioNetHdrLen+n])
	d.writePool.Put(bp)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (d *gsoDevice) Close() error {
	return d.f.Close()
}
