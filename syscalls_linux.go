package water

import (
	"os"
	"strings"
	"syscall"
	"unsafe"
)

const (
	cIFFTUN        = 0x0001
	cIFFTAP        = 0x0002
	cIFFNOPI       = 0x1000
	cIFFMULTIQUEUE = 0x0100
	cIFFVNETHDR    = 0x4000

	cTUNSETOFFLOAD = 0x400454d0
	cTUNFCSUM      = 0x01 // TUN_F_CSUM
	cTUNFTSO4      = 0x02 // TUN_F_TSO4
	cTUNFTSO6      = 0x04 // TUN_F_TSO6
)

type ifReq struct {
	Name  [0x10]byte
	Flags uint16
	pad   [0x28 - 0x10 - 2]byte
}

func ioctl(fd uintptr, request uintptr, argp uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(request), argp)
	if errno != 0 {
		return os.NewSyscallError("ioctl", errno)
	}
	return nil
}

func setupFd(config Config, fd uintptr) (name string, err error) {
	var flags uint16 = cIFFNOPI
	if config.DeviceType == TUN {
		flags |= cIFFTUN
	} else {
		flags |= cIFFTAP
	}
	if config.PlatformSpecificParams.MultiQueue {
		flags |= cIFFMULTIQUEUE
	}
	if config.PlatformSpecificParams.GSO {
		flags |= cIFFVNETHDR
	}

	if name, err = createInterface(fd, config.Name, flags); err != nil {
		return "", err
	}

	if err = setDeviceOptions(fd, config); err != nil {
		return "", err
	}

	if config.PlatformSpecificParams.GSO {
		// Enable TSO/CSUM so the kernel coalesces TCP/UDP into GSO super-frames
		// on read. The arg is passed by value (like TUNSETPERSIST), not by pointer.
		if err = ioctl(fd, cTUNSETOFFLOAD, uintptr(cTUNFCSUM|cTUNFTSO4|cTUNFTSO6)); err != nil {
			return "", err
		}
	}

	return name, nil
}

func createInterface(fd uintptr, ifName string, flags uint16) (createdIFName string, err error) {
	var req ifReq
	req.Flags = flags
	copy(req.Name[:], ifName)

	err = ioctl(fd, syscall.TUNSETIFF, uintptr(unsafe.Pointer(&req)))
	if err != nil {
		return
	}

	createdIFName = strings.Trim(string(req.Name[:]), "\x00")
	return
}

func setDeviceOptions(fd uintptr, config Config) (err error) {
	if config.Permissions != nil {
		if err = ioctl(fd, syscall.TUNSETOWNER, uintptr(config.Permissions.Owner)); err != nil {
			return
		}
		if err = ioctl(fd, syscall.TUNSETGROUP, uintptr(config.Permissions.Group)); err != nil {
			return
		}
	}

	// set clear the persist flag
	value := 0
	if config.Persist {
		value = 1
	}
	return ioctl(fd, syscall.TUNSETPERSIST, uintptr(value))
}
