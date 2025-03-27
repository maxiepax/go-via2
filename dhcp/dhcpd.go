package dhcp

import (
	"fmt"
	"net"

	//"github.com/davecgh/go-spew/spew"

	"errors"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mdlayher/raw"
	"github.com/sirupsen/logrus"

	"github.com/maxiepax/go-via2/db"
	"github.com/maxiepax/go-via2/models"
	"gorm.io/gorm"
)

func IPv4 (intf string) {
	// Select interface to used
	ifi, err := net.InterfaceByName(intf)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"if":  intf,
			"err": err,
		}).Fatalf("dhcp: failed to open interface")
	}

	// Find the ip-address
	ip, ipNet, err := findIPv4Addr(ifi)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"if":  intf,
			"err": err,
		}).Fatalf("dhcp: failed to get interface IPv4 address")
	}

	// Find the mac-address

	mac := ifi.HardwareAddr

	// Open a raw socket using ethertype 0x0800 (IPv4)
	c, err := raw.ListenPacket(ifi, 0x0800, &raw.Config{})
	if err != nil {
		logrus.Fatalf("dhcp: failed to listen: %v", err)
	}
	defer c.Close()

	logrus.WithFields(logrus.Fields{
		"mac": mac,
		"ip":  ip,
		"int": intf,
	}).Infof("Starting dhcp server")

	// Accept frames up to interface's MTU in size
	b := make([]byte, ifi.MTU)

	// Keep reading frames
	for {
		n, src, err := c.ReadFrom(b)
		if err != nil {
			logrus.Fatalf("dhcp: failed to receive message: %v", err)
		}

		packet := gopacket.NewPacket(b[:n], layers.LayerTypeEthernet, gopacket.Default)

		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)

		if ethLayer != nil && ipv4Layer != nil && udpLayer != nil && dhcpLayer != nil {
			eth, _ := ethLayer.(*layers.Ethernet)
			ipv4, _ := ipv4Layer.(*layers.IPv4)
			udp, _ := udpLayer.(*layers.UDP)
			req, _ := dhcpLayer.(*layers.DHCPv4)

			//spew.Dump(req)

			t := findMsgType(req)
			sourceNet := ip
			source := "broadcast"
			if ipNet != nil && !ipNet.Contains(ipv4.SrcIP) && !ipv4.SrcIP.Equal(net.IPv4zero) {
				sourceNet = ipv4.SrcIP
				source = "unicast"
			}

			if (req.RelayAgentIP != nil && !req.RelayAgentIP.Equal(net.IP{0, 0, 0, 0})) {
				sourceNet = req.RelayAgentIP
				source = "relayed"
			}

			resp, err := processPacket(t, req, sourceNet, ip)

			if err != nil {
				logrus.WithFields(logrus.Fields{
					"type":       t.String(),
					"client-mac": req.ClientHWAddr.String(),
					"source":     sourceNet.String(),
					"relay":      req.RelayAgentIP,
					"error":      err,
				}).Warnf("dhcp: failed to process %s %s", source, t)
				continue
			}

			// Copy some information from the request like option 82 (agent info) to the response
			resp.Flags = req.Flags
			for _, v := range req.Options {
				if v.Type == layers.DHCPOptClientID {
					resp.Options = append(resp.Options, v)
				}
				if v.Type == layers.DHCPOptHostname {
					resp.Options = append(resp.Options, v)
				}
				if v.Type == 82 {
					resp.Options = append(resp.Options, v)
				}
			}

			layers := buildHeaders(mac, ip, eth, ipv4, udp)
			layers = append(layers, resp)

			buf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}
			err = gopacket.SerializeLayers(buf, opts, layers...)
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"response":   findMsgType(resp).String(),
					"client-mac": req.ClientHWAddr.String(),
					"ip":         resp.YourClientIP,
					"relay":      req.RelayAgentIP,
				}).Warnf("dhcp: failed to serialise response to %s %s", source, t)
				continue
			}

			c.WriteTo(buf.Bytes(), src)

			//spew.Dump(resp)
			logrus.WithFields(logrus.Fields{
				"response":   findMsgType(resp).String(),
				"client-mac": req.ClientHWAddr.String(),
				"ip":         resp.YourClientIP,
				"relay":      req.RelayAgentIP,
			}).Infof("dhcp: answered %s %s with %s", source, t, findMsgType(resp))
			for _, v := range resp.Options {
				logrus.Debug(v)
			}
		}
	}
}

func findMsgType(p *layers.DHCPv4) layers.DHCPMsgType {
	var msgType layers.DHCPMsgType
	for _, o := range p.Options {
		if o.Type == layers.DHCPOptMessageType {
			msgType = layers.DHCPMsgType(o.Data[0])
		}
	}

	return msgType
}

func buildHeaders(mac net.HardwareAddr, ip net.IP, srcEth *layers.Ethernet, srcIP4 *layers.IPv4, srcUDP *layers.UDP) []gopacket.SerializableLayer {
	eth := &layers.Ethernet{
		SrcMAC:       mac,
		DstMAC:       srcEth.SrcMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		SrcIP:    ip,
		DstIP:    srcIP4.SrcIP,
		Version:  4,
		TOS:      0x10,
		TTL:      128,
		Protocol: layers.IPProtocolUDP,
		Flags:    layers.IPv4DontFragment,
	}

	udp := &layers.UDP{
		SrcPort: 67, // bootps
		DstPort: 67, // bootps
	}

	// Answer to broadcast address if source address is 0.0.0.0
	if srcIP4.SrcIP.Equal(net.IPv4zero) {
		ip4.DstIP = net.IPv4(255, 255, 255, 255)
		udp.DstPort = 68
	}

	udp.SetNetworkLayerForChecksum(ip4)

	return []gopacket.SerializableLayer{eth, ip4, udp}
}

func findIPv4Addr(ifi *net.Interface) (net.IP, *net.IPNet, error) {
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, nil, err
	}
	for _, addr := range addrs {
		switch v := addr.(type) {
		case *net.IPAddr:
			if addr := v.IP.To4(); addr != nil {
				return addr, nil, nil
			}
		case *net.IPNet:
			if addr := v.IP.To4(); addr != nil {
				return addr, v, nil
			}
		}
	}

	return nil, nil, fmt.Errorf("could not find IPv4 address")
}

func processPacket(t layers.DHCPMsgType, req *layers.DHCPv4, sourceNet net.IP, ip net.IP) (resp *layers.DHCPv4, err error) {
	switch t {
	case layers.DHCPMsgTypeDiscover:
		return processDiscover(req, sourceNet, ip)
	case layers.DHCPMsgTypeRequest:
		//return processRequest(req, sourceNet, ip)
	case layers.DHCPMsgTypeRelease:
		//return "Release"
	case layers.DHCPMsgTypeInform:
		return nil, fmt.Errorf("ignored, inform type")
	case layers.DHCPMsgTypeDecline:
		//return processDecline(req, sourceNet, ip)

	case layers.DHCPMsgTypeUnspecified:
		return nil, fmt.Errorf("ignored, unspecified type")
	case layers.DHCPMsgTypeOffer:
		return nil, fmt.Errorf("ignored, offer type")
	case layers.DHCPMsgTypeAck:
		return nil, fmt.Errorf("ignored, ack type")
	case layers.DHCPMsgTypeNak:
		return nil, fmt.Errorf("ignored, nak type")
	}

	return nil, fmt.Errorf("unknown dhcp request type")
}

func processDiscover(req *layers.DHCPv4, sourceNet net.IP, ip net.IP) (resp *layers.DHCPv4, err error) {
	// Find all reimage addresses that is not yet assigned a pool
	var host models.Host
	if res := db.DB.Where("mac", host.Mac).Where("reimage = 1").Find(&host); res.Error != nil {
		if !errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return nil, res.Error
		}
	}

	resp = &layers.DHCPv4{
		Operation:    layers.DHCPOpReply,
		HardwareType: layers.LinkTypeEthernet,
		Xid:          req.Xid,
		YourClientIP: net.ParseIP(host.IP),
		RelayAgentIP: req.RelayAgentIP,
		ClientHWAddr: req.ClientHWAddr,
		NextServerIP: ip.To4(),
	}

	resp.Options = append(resp.Options, layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeOffer)}))

	AddOptions1(req, resp, ip)

	//req *layers.DHCPv4, resp *layers.DHCPv4, pool models.PoolWithAddresses, lease *models.Address, ip net.IP

	return resp, nil
}

/*
func processRequest(req *layers.DHCPv4, sourceNet net.IP, ip net.IP) (*layers.DHCPv4, error) {


	// Find all reimage addresses that is not yet assigned a pool
	var reimageAddresses []models.Address
	if res := db.DB.Where("pool_id IS NULL").Where("reimage = 1").Find(&reimageAddresses); res.Error != nil {
		if !errors.Is(res.Error, gorm.ErrRecordNotFound) {
			return nil, res.Error
		}
	}

	// Figure out and get the pool
	pool, err := api.FindPool(sourceNet.String())
	if err != nil {
		return nil, err
	}

	// Make a list of all reimage and pool addresses
	addresses := append(reimageAddresses, pool.Addresses...)

	// Extract the requested IP
	var requestedIP net.IP = req.ClientIP
	for _, v := range req.Options {
		if v.Type == layers.DHCPOptRequestIP {
			requestedIP = net.IP(v.Data)
		}
	}

	// Start building the response
	resp := &layers.DHCPv4{
		Operation:    layers.DHCPOpReply,
		HardwareType: layers.LinkTypeEthernet,
		Xid:          req.Xid,
		RelayAgentIP: req.RelayAgentIP,
		ClientHWAddr: req.ClientHWAddr,
		NextServerIP: ip.To4(),
	}

	// Try to find the lease in our address list
	var lease *models.Address
	for _, v := range addresses {
		// Check so the IP is part of the pool
		parsedIp := net.ParseIP(v.IP)
		ok, _ := pool.Contains(parsedIp)

		// Check so we havent given someone else this IP
		err := pool.IsAvailableExcept(parsedIp, req.ClientHWAddr.String())

		if v.Mac == req.ClientHWAddr.String() && v.IP != requestedIP.String() && v.Expires.After(time.Now()) && ok && err == nil {
			logrus.WithFields(logrus.Fields{
				"pool":      pool.ID,
				"expected":  v.IP,
				"requested": requestedIP.String(),
			}).Warn("dhcp: wrong ip requested")
			resp.Options = append(resp.Options, layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeNak)}))
			return resp, nil
		}

		if v.Mac == req.ClientHWAddr.String() {
			foundLease := models.Address(v)
			lease = &foundLease
		}
	}

	// Check if the requested IP is available
	if lease == nil || lease.IP != requestedIP.String() {
		if err := pool.IsAvailable(requestedIP); err != nil {
			logrus.WithFields(logrus.Fields{
				"pool":      pool.ID,
				"requested": requestedIP.String(),
				"err":       err,
			}).Warnf("dhcp: the requested ip is not available")
			resp.Options = append(resp.Options, layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeNak)}))
			return resp, nil
		}
	}

	// Make sure the address isnt already used
	if lease != nil {
		if err := pool.IsAvailableExcept(requestedIP, req.ClientHWAddr.String()); err != nil {
			logrus.WithFields(logrus.Fields{
				"pool":      pool.ID,
				"requested": requestedIP.String(),
				"err":       err,
			}).Warnf("dhcp: the requested ip is not available (used by someone else)")
			resp.Options = append(resp.Options, layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeNak)}))
			return resp, nil
		}
	}

	// Dont answer pools with "only serve requested" flag set
	if pool.OnlyServeReimage && (lease == nil || !lease.Reimage) {
		return nil, fmt.Errorf("ignored because mac address is not flagged for reimaging")
	}

	// Its a new lease!
	if lease == nil {
		lease = &models.Address{
			AddressForm: models.AddressForm{
				Mac:      req.ClientHWAddr.String(),
				Hostname: "-",
				Reimage:  false,
			},
		}
	}

	// Respond with the same hostname
	for _, v := range req.Options {
		if v.Type == layers.DHCPOptHostname {
			lease.Hostname = string(v.Data)
		}
	}

	resp.YourClientIP = requestedIP

	resp.Options = append(resp.Options, layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeAck)}))
	AddOptions(req, resp, *pool, lease, ip)

	lease.IP = requestedIP.String()
	lease.PoolID = models.NullInt32{sql.NullInt32{int32(pool.ID), true}}
	lease.LastSeenRelay = req.RelayAgentIP.String()
	if (lease.FirstSeen == time.Time{}) {
		lease.FirstSeen = time.Now()
	}
	lease.LastSeen = time.Now()
	lease.Expires = time.Now().Add(3600 * time.Second)
	lease.MissingOptions = listMissingOptions(req, resp)

	if lease.ID == 0 {
		db.DB.Create(lease)
	} else {
		// Remove the previous record if there is any
		db.DB.Exec("DELETE FROM addresses WHERE ip=? AND reimage=0 AND expires <= datetime('now', 'utc')", lease.IP)
		db.DB.Save(lease)
	}

	return resp, nil
}

func listMissingOptions(req *layers.DHCPv4, resp *layers.DHCPv4) string {
	requested := map[byte]struct{}{}
	for _, v := range req.Options {
		if v.Type == layers.DHCPOptParamsRequest {
			for _, v := range v.Data {
				requested[v] = struct{}{}
			}
		}
	}

	for _, v := range resp.Options {
		if _, ok := requested[byte(v.Type)]; ok {
			delete(requested, byte(v.Type))
		}
	}

	var list []string
	for k := range requested {
		list = append(list, strconv.Itoa(int(k)))
	}

	return strings.Join(list, ",")
}

// a IP address conflict was detected, add/update the address table to block that address from being used for a while (lease time)
func processDecline(req *layers.DHCPv4, sourceNet net.IP, ip net.IP) (*layers.DHCPv4, error) {

	pool, err := api.FindPool(sourceNet.String())
	if err != nil {
		return nil, err
	}

	var requestedIP net.IP
	for _, v := range req.Options {
		if v.Type == layers.DHCPOptRequestIP {
			requestedIP = net.IP(v.Data)
		}
	}

	// Try to find the lease in our address history
	var lease *models.Address
	for _, v := range pool.Addresses {
		if v.IP == requestedIP.To4().String() {
			lease = &v
		}
	}

	// Its an unknown device
	if lease == nil {
		lease = &models.Address{
			AddressForm: models.AddressForm{
				IP:       requestedIP.String(),
				Hostname: "-",
				Reimage:  false,
			},
		}
	}

	lease.Mac = ""
	lease.PoolID = models.NullInt32{sql.NullInt32{int32(pool.ID), true}}
	lease.LastSeenRelay = req.RelayAgentIP.String()
	lease.LastSeen = time.Now()
	lease.Expires = time.Now().Add(3600 * time.Second)

	if lease.ID == 0 {
		db.DB.Create(lease)
	} else {
		db.DB.Save(lease)
	}

	return nil, nil
}
*/

func AddOptions1(req *layers.DHCPv4, resp *layers.DHCPv4, ip net.IP) error {

for _, options := range req.Options {
	if options.Type == layers.DHCPOptParamsRequest {
		for _, v := range options.Data {
			spew.Dump(v)
		}
	}
}

/*
for _, v := range req.Options {

	if v.Type == layers.DHCPOptParamsRequest {
		spew.Dump(v)
		for k1, v1 := range v.Data {
			fmt.Println("k: ", k1)
			fmt.Println("v: ", v1)
			fmt.Println("---")
		}
	}
}
*/

/*
case 67:
	resp.Options = append(resp.Options, layers.NewDHCPOption(code, []byte("mboot.efi")))
*/
//spew.Dump(req.Options)

/*
	Parameter-Request (55), length 27:
	Subnet-Mask (1), Time-Zone (2), Default-Gateway (3), Time-Server (4)
	IEN-Name-Server (5), Domain-Name-Server (6), Hostname (12), BS (13)
	Domain-Name (15), RP (17), EP (18), RSZ (22)
	TTL (23), BR (28), YD (40), YS (41)
	NTP (42), Vendor-Option (43), Requested-IP (50), Lease-Time (51)
	Server-ID (54), RN (58), RB (59), Vendor-Class (60)
	Unknown (253), BF (67), GUID (97)

*/
	return nil

}

/*
// AddOptions will try to add all requested options and the manually specified ones to the response
func AddOptions(req *layers.DHCPv4, resp *layers.DHCPv4, pool models.PoolWithAddresses, lease *models.Address, ip net.IP) error {
	var options []models.Option
	var leaseID interface{}

	if lease != nil {
		leaseID = lease.ID
	}

	// Try to find the device class
	var deviceClass models.DeviceClass
	for _, v := range req.Options {
		if v.Type == 60 { // Vendor class
			db.DB.Where("? LIKE '%' || vendor_class || '%'", string(v.Data)).First(&deviceClass)
		}
	}

	if res := db.DB.Where("((pool_id = 0 AND device_class_id = 0 AND address_id = 0) OR pool_id = ? OR address_id = ?) AND (device_class_id = 0 OR device_class_id = ?)", pool.ID, leaseID, deviceClass.ID).Order("device_class_id desc").Order("address_id desc").Order("pool_id desc").Find(&options); res.Error != nil && !errors.Is(res.Error, gorm.ErrRecordNotFound) {

		return res.Error
	}

	// Group options by opcode
	byOpCode := make(map[byte][]models.Option)
	for _, v := range options {
		if byOpCode[v.OpCode] == nil {
			byOpCode[v.OpCode] = make([]models.Option, 0)
		}

		// Only add the highest level options to the list
		// The level is decided on pool_id and address_id fields
		// addess+device_class specific = 5
		// pool+device_class specific = 4
		// global+device_class = 3
		// addess specific = 2
		// pool specific = 1
		// global = 0
		if len(byOpCode[v.OpCode]) == 0 || v.Level() >= byOpCode[v.OpCode][0].Level() {
			byOpCode[v.OpCode] = append(byOpCode[v.OpCode], v)
		}
	}

	// Extract the order of the requested options
	requestedOptions := map[byte]struct{}{}
	for _, v := range req.Options {
		if v.Type == layers.DHCPOptParamsRequest {
			for _, v := range v.Data {
				requestedOptions[v] = struct{}{}
			}
		}
	}

	defaultOptions := []byte{
		byte(layers.DHCPOptT1),
		byte(layers.DHCPOptT2),
		byte(layers.DHCPOptLeaseTime),
		byte(layers.DHCPOptServerID),
		//byte(66),
		byte(67),
	}
	for _, v := range defaultOptions {
		if _, ok := requestedOptions[v]; !ok {
			requestedOptions[v] = struct{}{}
		}
	}

	// Add the requested options to the response
	var leaseTime float64 = float64(pool.LeaseTime)
	if leaseTime == 0 {
		leaseTime = 3600
	}
	for opCode := range requestedOptions {
		if options, ok := byOpCode[opCode]; ok {
			for _, v := range options {
				dhcpOpt, _, err := v.ToDHCPOption() // TODO: fix merge
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"opcode": opCode,
						"name":   layers.DHCPOpt(opCode).String(),
						"err":    err,
					}).Error("dhcp: failed to encode dhcp option")
					continue
				}

				resp.Options = append(resp.Options, dhcpOpt)
			}
			delete(byOpCode, opCode)
			continue
		}

		// Try to generate the missing option
		code := layers.DHCPOpt(opCode)
		switch code {

		case 67:
			resp.Options = append(resp.Options, layers.NewDHCPOption(code, []byte("mboot.efi")))
		case layers.DHCPOptSubnetMask:
			resp.Options = append(resp.Options, layers.NewDHCPOption(code, net.CIDRMask(pool.Netmask, 32)))
		case layers.DHCPOptClasslessStaticRoute:
			var b bytes.Buffer
			b.Write([]byte{byte(pool.Netmask)})

			// Only write the non-zero octets.
			dstLen := (pool.Netmask + 7) / 8
			b.Write(net.ParseIP(pool.Gateway).To4()[:dstLen])

			b.Write(net.ParseIP(pool.Gateway).To4())
			resp.Options = append(resp.Options, layers.NewDHCPOption(code, b.Bytes()))
		case layers.DHCPOptRouter:
			resp.Options = append(resp.Options, layers.NewDHCPOption(code, net.ParseIP(pool.Gateway).To4()))
		case layers.DHCPOptBroadcastAddr:
			b, err := pool.LastAddr()
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"opcode": opCode,
					"name":   layers.DHCPOpt(opCode).String(),
					"err":    err,
				}).Warn("dhcp: could not get broadcast address")
				continue
			}

			resp.Options = append(resp.Options, layers.NewDHCPOption(code, b))
		case layers.DHCPOptT1:
			resp.Options = append(resp.Options, models.NewUint32Option(layers.DHCPOptT1, int(leaseTime*0.5))) // renewal time
		case layers.DHCPOptT2:
			resp.Options = append(resp.Options, models.NewUint32Option(layers.DHCPOptT2, int(leaseTime*0.875))) // rebind time
		case layers.DHCPOptLeaseTime:
			resp.Options = append(resp.Options, models.NewUint32Option(layers.DHCPOptLeaseTime, int(leaseTime))) // lease time
		case layers.DHCPOptServerID:
			resp.Options = append(resp.Options, layers.NewDHCPOption(code, ip))
		default:
			// Everything failed :/
			logrus.WithFields(logrus.Fields{
				"opcode": opCode,
				"name":   layers.DHCPOpt(opCode).String(),
			}).Debug("dhcp: could not find the requested option", opCode, layers.DHCPOpt(opCode).String())
		}

	}

	// Add the remaining options (that werent requested) in the end
	for opCode, options := range byOpCode {
		for _, v := range options {
			dhcpOpt, _, err := v.ToDHCPOption() // TODO: fix merge
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"opcode": opCode,
					"name":   layers.DHCPOpt(opCode).String(),
					"err":    err,
				}).Error("dhcp: failed to encode dhcp option")
				continue
			}

			resp.Options = append(resp.Options, dhcpOpt)
		}
	}

	return nil
}
	*/