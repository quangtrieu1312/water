// +build linux,go1.11

package water

import (
	"io"
	"os"
	"syscall"
)

func openDev(config Config) (ifce *Interface, err error) {
	var fdInt int
	if fdInt, err = syscall.Open(
		"/dev/net/tun", os.O_RDWR|syscall.O_NONBLOCK, 0); err != nil {
		return nil, err
	}

	name, err := setupFd(config, uintptr(fdInt))
	if err != nil {
		return nil, err
	}

	f := os.NewFile(uintptr(fdInt), "tun")
	var rwc io.ReadWriteCloser = f
	if config.PlatformSpecificParams.GSO {
		rwc = newGSODevice(f)
	}

	return &Interface{
		isTAP:           config.DeviceType == TAP,
		ReadWriteCloser: rwc,
		name:            name,
	}, nil
}
