package dhcp

import (
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
)

func IPv4() {
	conn, err := net.ListenPacket("udp4", ":67")
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Info("dhcpd4")
        return
    } else {
		logrus.WithFields(logrus.Fields{
			"info": "Listening for dhcp ipv4 packets on port 67",
		}).Info("dhcpd4")
    }
	defer conn.Close()

	for {
        buffer := make([]byte, 1500) // Standard MTU size
        _, addr, err := conn.ReadFrom(buffer)
        if err != nil {
            logrus.WithFields(logrus.Fields{
				"error": err,
			}).Info("dhcpd4")
            continue
        }

        if ipV4Discover(buffer) {
            fmt.Printf("DHCP Discover received from %v\n", addr)
        }
    }
}

func ipV4Discover(packet []byte) bool {
    // Ensure packet length is sufficient for DHCP (minimum 240 bytes + options)
    if len(packet) < 244 {
        return false
    }

    // Check if the message type is BOOTREQUEST (1)
    if packet[0] != 1 {
        return false
    }

    // DHCP options start at byte 240
    options := packet[240:]

    for i := 0; i < len(options); {
        optionType := options[i]
        i++

        // End Option
        if optionType == 255 {
            break
        }

        optionLen := int(options[i])
        i++

        // DHCP Message Type option
        if optionType == 53 && optionLen == 1 && options[i] == 1 { // 1 = DHCP Discover
            return true
        }

        i += optionLen
    }

    return false
}