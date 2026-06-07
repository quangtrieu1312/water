package water

// GSO/GRO offload helpers for the Linux IFF_VNET_HDR path.
//
// Adapted from WireGuard-go (tun/offload_linux.go, tun/tun_linux.go), which is
// MIT-licensed (Copyright (C) 2017-2023 WireGuard LLC). Only the RECEIVE-side
// split (virtio_net_hdr decode + TCP/UDP GSO segmentation reversal) is kept;
// the GRO write-coalescing tables are intentionally omitted for now. The unix.*
// constants are inlined so this package keeps no external dependency.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"unsafe"
)

// virtio_net.h constants (include/uapi/linux/virtio_net.h) + TUN offload flags.
const (
	virtioNetHdrFNeedsCsum = 1 // VIRTIO_NET_HDR_F_NEEDS_CSUM

	virtioNetHdrGSONone  = 0 // VIRTIO_NET_HDR_GSO_NONE
	virtioNetHdrGSOTCPV4 = 1 // VIRTIO_NET_HDR_GSO_TCPV4
	virtioNetHdrGSOTCPV6 = 4 // VIRTIO_NET_HDR_GSO_TCPV6
	virtioNetHdrGSOUDPL4 = 5 // VIRTIO_NET_HDR_GSO_UDP_L4

	protoTCP = 6  // IPPROTO_TCP
	protoUDP = 17 // IPPROTO_UDP

	tcpFlagsOffset = 13
	tcpFlagFIN     = 0x01
	tcpFlagPSH     = 0x08

	ipv4SrcAddrOffset = 12
	ipv6SrcAddrOffset = 8
)

// ErrTooManySegments is returned when a GSO frame splits into more segments
// than the caller provided output buffers for.
var ErrTooManySegments = errors.New("water: too many GSO segments")

// virtioNetHdr is defined in include/uapi/linux/virtio_net.h.
type virtioNetHdr struct {
	flags      uint8
	gsoType    uint8
	hdrLen     uint16
	gsoSize    uint16
	csumStart  uint16
	csumOffset uint16
}

// virtioNetHdrLen is the length in bytes of virtioNetHdr (10).
const virtioNetHdrLen = int(unsafe.Sizeof(virtioNetHdr{}))

func (v *virtioNetHdr) decode(b []byte) error {
	if len(b) < virtioNetHdrLen {
		return io_ErrShortBuffer
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(v)), virtioNetHdrLen), b[:virtioNetHdrLen])
	return nil
}

func (v *virtioNetHdr) encode(b []byte) error {
	if len(b) < virtioNetHdrLen {
		return io_ErrShortBuffer
	}
	copy(b[:virtioNetHdrLen], unsafe.Slice((*byte)(unsafe.Pointer(v)), virtioNetHdrLen))
	return nil
}

var io_ErrShortBuffer = errors.New("water: short virtio buffer")

// handleVirtioRead splits a single read() of an IFF_VNET_HDR tun fd into one or
// more IP packets, written into bufs[i][offset:], returning the number of
// packets and their sizes (in sizes[i]).
func handleVirtioRead(in []byte, bufs [][]byte, sizes []int, offset int) (int, error) {
	var hdr virtioNetHdr
	if err := hdr.decode(in); err != nil {
		return 0, err
	}
	in = in[virtioNetHdrLen:]
	if hdr.gsoType == virtioNetHdrGSONone {
		if hdr.flags&virtioNetHdrFNeedsCsum != 0 {
			if err := gsoNoneChecksum(in, hdr.csumStart, hdr.csumOffset); err != nil {
				return 0, err
			}
		}
		if len(in) > len(bufs[0][offset:]) {
			return 0, fmt.Errorf("read len %d overflows bufs element len %d", len(in), len(bufs[0][offset:]))
		}
		n := copy(bufs[0][offset:], in)
		sizes[0] = n
		return 1, nil
	}
	if hdr.gsoType != virtioNetHdrGSOTCPV4 && hdr.gsoType != virtioNetHdrGSOTCPV6 && hdr.gsoType != virtioNetHdrGSOUDPL4 {
		return 0, fmt.Errorf("unsupported virtio GSO type: %d", hdr.gsoType)
	}

	ipVersion := in[0] >> 4
	switch ipVersion {
	case 4:
		if hdr.gsoType != virtioNetHdrGSOTCPV4 && hdr.gsoType != virtioNetHdrGSOUDPL4 {
			return 0, fmt.Errorf("ip header version: %d, GSO type: %d", ipVersion, hdr.gsoType)
		}
	case 6:
		if hdr.gsoType != virtioNetHdrGSOTCPV6 && hdr.gsoType != virtioNetHdrGSOUDPL4 {
			return 0, fmt.Errorf("ip header version: %d, GSO type: %d", ipVersion, hdr.gsoType)
		}
	default:
		return 0, fmt.Errorf("invalid ip header version: %d", ipVersion)
	}

	// Don't trust hdr.hdrLen from the kernel; derive it from the transport header.
	if hdr.gsoType == virtioNetHdrGSOUDPL4 {
		hdr.hdrLen = hdr.csumStart + 8
	} else {
		if len(in) <= int(hdr.csumStart+12) {
			return 0, errors.New("packet is too short")
		}
		tcpHLen := uint16(in[hdr.csumStart+12] >> 4 * 4)
		if tcpHLen < 20 || tcpHLen > 60 {
			return 0, fmt.Errorf("tcp header len is invalid: %d", tcpHLen)
		}
		hdr.hdrLen = hdr.csumStart + tcpHLen
	}

	if len(in) < int(hdr.hdrLen) {
		return 0, fmt.Errorf("length of packet (%d) < virtioNetHdr.hdrLen (%d)", len(in), hdr.hdrLen)
	}
	if hdr.hdrLen < hdr.csumStart {
		return 0, fmt.Errorf("virtioNetHdr.hdrLen (%d) < virtioNetHdr.csumStart (%d)", hdr.hdrLen, hdr.csumStart)
	}
	cSumAt := int(hdr.csumStart + hdr.csumOffset)
	if cSumAt+1 >= len(in) {
		return 0, fmt.Errorf("end of checksum offset (%d) exceeds packet length (%d)", cSumAt+1, len(in))
	}

	return gsoSplit(in, hdr, bufs, sizes, offset, ipVersion == 6)
}

func gsoSplit(in []byte, hdr virtioNetHdr, outBuffs [][]byte, sizes []int, outOffset int, isV6 bool) (int, error) {
	iphLen := int(hdr.csumStart)
	srcAddrOffset := ipv6SrcAddrOffset
	addrLen := 16
	if !isV6 {
		in[10], in[11] = 0, 0 // clear ipv4 header checksum
		srcAddrOffset = ipv4SrcAddrOffset
		addrLen = 4
	}
	transportCsumAt := int(hdr.csumStart + hdr.csumOffset)
	in[transportCsumAt], in[transportCsumAt+1] = 0, 0 // clear tcp/udp checksum
	var firstTCPSeqNum uint32
	var protocol uint8
	if hdr.gsoType == virtioNetHdrGSOTCPV4 || hdr.gsoType == virtioNetHdrGSOTCPV6 {
		protocol = protoTCP
		firstTCPSeqNum = binary.BigEndian.Uint32(in[hdr.csumStart+4:])
	} else {
		protocol = protoUDP
	}
	nextSegmentDataAt := int(hdr.hdrLen)
	i := 0
	for ; nextSegmentDataAt < len(in); i++ {
		if i == len(outBuffs) {
			return i - 1, ErrTooManySegments
		}
		nextSegmentEnd := nextSegmentDataAt + int(hdr.gsoSize)
		if nextSegmentEnd > len(in) {
			nextSegmentEnd = len(in)
		}
		segmentDataLen := nextSegmentEnd - nextSegmentDataAt
		totalLen := int(hdr.hdrLen) + segmentDataLen
		sizes[i] = totalLen
		out := outBuffs[i][outOffset:]
		if totalLen > len(out) {
			// segment larger than the per-segment buffer; skip the frame rather than
			// panic on the out[:totalLen] slices below. Trips only on an inner MTU that
			// exceeds gsoSegBufSize (raise it for jumbo underlays).
			return i, fmt.Errorf("segment %d len %d exceeds seg buffer %d (raise gsoSegBufSize)", i, totalLen, len(out))
		}

		copy(out, in[:iphLen])
		if !isV6 {
			if i > 0 {
				id := binary.BigEndian.Uint16(out[4:])
				id += uint16(i)
				binary.BigEndian.PutUint16(out[4:], id)
			}
			binary.BigEndian.PutUint16(out[2:], uint16(totalLen))
			ipv4CSum := ^checksum(out[:iphLen], 0)
			binary.BigEndian.PutUint16(out[10:], ipv4CSum)
		} else {
			binary.BigEndian.PutUint16(out[4:], uint16(totalLen-iphLen))
		}

		copy(out[hdr.csumStart:hdr.hdrLen], in[hdr.csumStart:hdr.hdrLen])

		if protocol == protoTCP {
			tcpSeq := firstTCPSeqNum + uint32(hdr.gsoSize*uint16(i))
			binary.BigEndian.PutUint32(out[hdr.csumStart+4:], tcpSeq)
			if nextSegmentEnd != len(in) {
				var clearFlags byte = tcpFlagFIN | tcpFlagPSH
				out[hdr.csumStart+tcpFlagsOffset] &^= clearFlags
			}
		} else {
			binary.BigEndian.PutUint16(out[hdr.csumStart+4:], uint16(segmentDataLen)+(hdr.hdrLen-hdr.csumStart))
		}

		copy(out[hdr.hdrLen:], in[nextSegmentDataAt:nextSegmentEnd])

		transportHeaderLen := int(hdr.hdrLen - hdr.csumStart)
		lenForPseudo := uint16(transportHeaderLen + segmentDataLen)
		transportCSumNoFold := pseudoHeaderChecksumNoFold(protocol, in[srcAddrOffset:srcAddrOffset+addrLen], in[srcAddrOffset+addrLen:srcAddrOffset+addrLen*2], lenForPseudo)
		transportCSum := ^checksum(out[hdr.csumStart:totalLen], transportCSumNoFold)
		binary.BigEndian.PutUint16(out[hdr.csumStart+hdr.csumOffset:], transportCSum)

		nextSegmentDataAt += int(hdr.gsoSize)
	}
	return i, nil
}

func gsoNoneChecksum(in []byte, cSumStart, cSumOffset uint16) error {
	cSumAt := cSumStart + cSumOffset
	initial := binary.BigEndian.Uint16(in[cSumAt:])
	in[cSumAt], in[cSumAt+1] = 0, 0
	binary.BigEndian.PutUint16(in[cSumAt:], ^checksum(in[cSumStart:], uint64(initial)))
	return nil
}

func checksumNoFold(b []byte, initial uint64) uint64 {
	tmp := make([]byte, 8)
	binary.NativeEndian.PutUint64(tmp, initial)
	ac := binary.BigEndian.Uint64(tmp)
	var carry uint64
	for len(b) >= 8 {
		ac, carry = bits.Add64(ac, binary.NativeEndian.Uint64(b[:8]), 0)
		ac += carry
		b = b[8:]
	}
	if len(b) >= 4 {
		ac, carry = bits.Add64(ac, uint64(binary.NativeEndian.Uint32(b[:4])), 0)
		ac += carry
		b = b[4:]
	}
	if len(b) >= 2 {
		ac, carry = bits.Add64(ac, uint64(binary.NativeEndian.Uint16(b[:2])), 0)
		ac += carry
		b = b[2:]
	}
	if len(b) == 1 {
		ac, carry = bits.Add64(ac, uint64(binary.NativeEndian.Uint16([]byte{b[0], 0})), 0)
		ac += carry
	}
	binary.NativeEndian.PutUint64(tmp, ac)
	return binary.BigEndian.Uint64(tmp)
}

func checksum(b []byte, initial uint64) uint16 {
	ac := checksumNoFold(b, initial)
	ac = (ac >> 16) + (ac & 0xffff)
	ac = (ac >> 16) + (ac & 0xffff)
	ac = (ac >> 16) + (ac & 0xffff)
	ac = (ac >> 16) + (ac & 0xffff)
	return uint16(ac)
}

func pseudoHeaderChecksumNoFold(protocol uint8, srcAddr, dstAddr []byte, totalLen uint16) uint64 {
	sum := checksumNoFold(srcAddr, 0)
	sum = checksumNoFold(dstAddr, sum)
	sum = checksumNoFold([]byte{0, protocol}, sum)
	tmp := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, totalLen)
	return checksumNoFold(tmp, sum)
}
