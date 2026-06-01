package water

import (
	"encoding/binary"
	"testing"
)

// build a virtio GSO_TCPV4 frame: [virtioNetHdr][IPv4 hdr][TCP hdr][payload]
func buildTCPv4GSO(payloadLen, gsoSize int) []byte {
	const iphLen, tcphLen = 20, 20
	total := virtioNetHdrLen + iphLen + tcphLen + payloadLen
	b := make([]byte, total)

	// virtio_net_hdr
	hdr := virtioNetHdr{
		flags:      virtioNetHdrFNeedsCsum,
		gsoType:    virtioNetHdrGSOTCPV4,
		hdrLen:     uint16(iphLen + tcphLen),
		gsoSize:    uint16(gsoSize),
		csumStart:  uint16(iphLen),
		csumOffset: 16, // TCP checksum offset
	}
	_ = hdr.encode(b)

	ip := b[virtioNetHdrLen:]
	ip[0] = 0x45 // v4, ihl=5
	binary.BigEndian.PutUint16(ip[2:], uint16(iphLen+tcphLen+payloadLen))
	binary.BigEndian.PutUint16(ip[4:], 0x1234) // id
	ip[8] = 64                                  // ttl
	ip[9] = protoTCP
	copy(ip[12:16], []byte{10, 0, 0, 1})  // src
	copy(ip[16:20], []byte{10, 0, 0, 2})  // dst

	tcp := ip[iphLen:]
	binary.BigEndian.PutUint16(tcp[0:], 1000)  // sport
	binary.BigEndian.PutUint16(tcp[2:], 2000)  // dport
	binary.BigEndian.PutUint32(tcp[4:], 5000)  // seq
	tcp[12] = 5 << 4                           // data offset = 5 (20 bytes)
	tcp[13] = 0x18                             // PSH|ACK
	for i := 0; i < payloadLen; i++ {
		tcp[tcphLen+i] = byte(i)
	}
	return b
}

// a valid IPv4 header checksums (one's complement sum incl. csum field) to 0xFFFF.
func ipv4HdrValid(ip []byte) bool { return checksum(ip[:20], 0) == 0xffff }

// a valid TCP segment: checksum over pseudo-header + TCP header + payload == 0xFFFF.
func tcpSegValid(ip []byte) bool {
	totalLen := int(binary.BigEndian.Uint16(ip[2:]))
	tcp := ip[20:totalLen]
	pseudo := pseudoHeaderChecksumNoFold(protoTCP, ip[12:16], ip[16:20], uint16(len(tcp)))
	return checksum(tcp, pseudo) == 0xffff
}

func TestGSOSplitTCPv4(t *testing.T) {
	cases := []struct{ payload, gso int }{
		{3000, 1000}, // exact 3 segments
		{2500, 1000}, // 3 segments, last short
		{500, 1000},  // single short segment
		{8192, 1448}, // realistic MSS
	}
	for _, c := range cases {
		in := buildTCPv4GSO(c.payload, c.gso)
		bufs := make([][]byte, gsoMaxSegments)
		sizes := make([]int, gsoMaxSegments)
		for i := range bufs {
			bufs[i] = make([]byte, gsoSegBufSize)
		}
		n, err := handleVirtioRead(in, bufs, sizes, 0)
		if err != nil {
			t.Fatalf("payload=%d gso=%d: handleVirtioRead err: %v", c.payload, c.gso, err)
		}
		wantSegs := (c.payload + c.gso - 1) / c.gso
		if n != wantSegs {
			t.Errorf("payload=%d gso=%d: got %d segs want %d", c.payload, c.gso, n, wantSegs)
		}
		var seenPayload, baseSeq int = 0, 5000
		for i := 0; i < n; i++ {
			seg := bufs[i][:sizes[i]]
			if !ipv4HdrValid(seg) {
				t.Errorf("payload=%d gso=%d seg%d: bad IPv4 checksum", c.payload, c.gso, i)
			}
			if !tcpSegValid(seg) {
				t.Errorf("payload=%d gso=%d seg%d: bad TCP checksum", c.payload, c.gso, i)
			}
			gotSeq := binary.BigEndian.Uint32(seg[24:])
			if int(gotSeq) != baseSeq+seenPayload {
				t.Errorf("payload=%d gso=%d seg%d: seq=%d want %d", c.payload, c.gso, i, gotSeq, baseSeq+seenPayload)
			}
			seenPayload += sizes[i] - 40
		}
		if seenPayload != c.payload {
			t.Errorf("payload=%d gso=%d: reassembled payload %d", c.payload, c.gso, seenPayload)
		}
	}
}
