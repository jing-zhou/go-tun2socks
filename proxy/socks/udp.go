package socks

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/eycorsican/go-tun2socks/common/dns"
	"github.com/eycorsican/go-tun2socks/common/log"
	"github.com/eycorsican/go-tun2socks/component/pool"
	"github.com/eycorsican/go-tun2socks/core"
)

// max IP packet size - min IP header size - min UDP header size - min SOCKS5 header size
const maxUdpPayloadSize = 65535 - 20 - 8 - 7

var (
	natTable = &sync.Map{}
)

type natTableEntry struct {
	udpConn    net.PacketConn
	tcpConn    net.Conn
	remoteAddr *net.UDPAddr // UDP relay server addresses
}

type udpHandler struct {
	proxyHost string
	proxyPort uint16
	timeout   time.Duration
	dnsCache  dns.DnsCache
	fakeDns   dns.FakeDns
}

func NewUDPHandler(proxyHost string, proxyPort uint16, timeout time.Duration, dnsCache dns.DnsCache, fakeDns dns.FakeDns) core.UDPConnHandler {
	return &udpHandler{
		proxyHost: proxyHost,
		proxyPort: proxyPort,
		dnsCache:  dnsCache,
		fakeDns:   fakeDns,
		timeout:   timeout,
	}
}

func (h *udpHandler) handleTCP(conn core.UDPConn, c net.Conn) {
	buf := pool.NewBytes(pool.BufSize)
	defer pool.FreeBytes(buf)
	defer h.Close(conn)

	for {
		// Don't timeout
		c.SetDeadline(time.Time{})
		_, err := io.CopyBuffer(ioutil.Discard, c, buf)
		if err == io.EOF {
			log.Infof("UDP associate to %v closed by remote", c.RemoteAddr())
		} else if err != nil {
			log.Warnf("UDP associate to %v closed unexpectedly by remote, err: %v", c.RemoteAddr(), err)
		}
		return
	}
}

func (h *udpHandler) fetchUDPInput(conn core.UDPConn, input net.PacketConn) {
	buf := pool.NewBytes(maxUdpPayloadSize)
	var err error
	var bytesRead int
	//var bytesWritten int
	var resolvedAddr *net.UDPAddr

	defer func(conn core.UDPConn, buf []byte) {
		h.Close(conn)
		pool.FreeBytes(buf)
	}(conn, buf)

	for {
		input.SetDeadline(time.Now().Add(h.timeout))
		bytesRead, _, err = input.ReadFrom(buf)
		if err != nil {
			log.Warnf("read remote failed: %v", err)
			return
		}
		if bytesRead < 3 {
			continue
		}
		//log.Debugf("input.Readfrom %v", buf[:bytesRead])
		addr := SplitAddr(buf[3:bytesRead])
		if addr == nil {
			continue
		}
		addrLen := len(addr)
		addrStr := addr.String()
		var payloadPos int = 3 + addrLen
		resolvedAddr, err = net.ResolveUDPAddr("udp", addrStr)
		if err != nil {
			continue
		}
		//log.Debugf("udp resolvedAddr: %v", resolvedAddr)
		//log.Debugf("payloadPos: %v", payloadPos)
		//log.Debugf("before conn.WriteFrom %v", buf[payloadPos:bytesRead])
		_ /*bytesWritten*/, err = conn.WriteFrom(buf[payloadPos:bytesRead], resolvedAddr)
		//log.Debugf("after conn.WriteFrom %v", buf[payloadPos:payloadPos+bytesWritten])
		if err != nil {
			log.Warnf("write local failed: %v", err)
			return
		}

		if h.dnsCache != nil {
			var port string
			var portnum uint64
			_, port, err = net.SplitHostPort(addrStr)
			if err != nil {
				log.Warnf("fetchUDPInput: SplitHostPort failed with %v", err)
				return
			}
			portnum, err = strconv.ParseUint(port, 10, 16)
			if portnum == uint64(dns.COMMON_DNS_PORT) {
				err = h.dnsCache.Store(buf[payloadPos:bytesRead])
				if err != nil {
					log.Warnf("fetchUDPInput: fail to store in DnsCache: %v", err)
				}
				return // DNS response
			}
		}
	}
}

func (h *udpHandler) Connect(conn core.UDPConn, target *net.UDPAddr) error {
	if target == nil {
		return h.connectInternal(conn, "")
	}

	// Replace with a domain name if target address IP is a fake IP.
	targetHost := target.IP.String()
	if h.fakeDns != nil {
		if target.Port == dns.COMMON_DNS_PORT {
			return nil // skip dns
		}
		if h.fakeDns.IsFakeIP(target.IP) {
			targetHost = h.fakeDns.QueryDomain(target.IP)
		}
	}
	dest := net.JoinHostPort(targetHost, strconv.Itoa(target.Port))

	return h.connectInternal(conn, dest)
}

func (h *udpHandler) connectInternal(conn core.UDPConn, dest string) error {
	log.Infof("connectInternal: dest is %v", dest)
	c, err := net.DialTimeout("tcp", core.ParseTCPAddr(h.proxyHost, h.proxyPort).String(), 30*time.Second)
	if err != nil {
		return err
	}

	// tcp set keepalive
	tcpKeepAlive(c)

	c.SetDeadline(time.Now().Add(30 * time.Second))

	// send VER, NMETHODS, METHODS
	c.Write([]byte{5, 1, 0})

	buf := make([]byte, MaxAddrLen)
	// read VER METHOD
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return err
	}

	c.Write(append([]byte{5, socks5UDPAssociate, 0}, []byte{1, 0, 0, 0, 0, 0, 0}...))

	// read VER REP RSV ATYP BND.ADDR BND.PORT
	if _, err := io.ReadFull(c, buf[:3]); err != nil {
		return err
	}

	rep := buf[1]
	if rep != 0 {
		return errors.New("SOCKS handshake failed")
	}

	remoteAddr, err := readAddr(c, buf)
	if err != nil {
		return err
	}

	resolvedRemoteAddr, err := net.ResolveUDPAddr("udp", remoteAddr.String())
	if err != nil {
		return errors.New("failed to resolve remote address")
	}

	go h.handleTCP(conn, c)

	pc, err := net.ListenPacket("udp", "")
	if err != nil {
		return err
	}
	connKey := getConnKey(conn)
	natTable.Store(connKey, &natTableEntry{
		tcpConn:    c,
		udpConn:    pc,
		remoteAddr: resolvedRemoteAddr,
	})

	go h.fetchUDPInput(conn, pc)

	if len(dest) != 0 {
		var process string = "N/A"
		log.Access(process, "proxy", "udp", conn.LocalAddr().String(), dest)
	}
	return nil
}

func (h *udpHandler) ReceiveTo(conn core.UDPConn, data []byte, addr *net.UDPAddr) error {
	var err error
	var pc net.PacketConn
	var remoteAddr *net.UDPAddr
	defer func(err *error) {
		if *err != nil {
			log.Infof("ReceiveTo: Call close in defered func")
			h.Close(conn)
		}
	}(&err)
	connKey := getConnKey(conn)

	if addr.Port == dns.COMMON_DNS_PORT {
		// fetch from dns cache first
		if h.dnsCache != nil {
			var answer []byte
			answer, err = h.dnsCache.Query(data)
			if err != nil {
				return err
			}
			if answer != nil {
				_, err = conn.WriteFrom(answer, addr)
				if err != nil {
					err = errors.New(fmt.Sprintf("write dns answer failed: %v", err))
					return err
				}
				h.Close(conn)
				return nil
			}
		}

		// dns cache miss, do the query
		if h.fakeDns != nil {
			var resp []byte
			resp, err = h.fakeDns.GenerateFakeResponse(data)
			if err != nil {
				// FIXME This will block the lwip thread, need to optimize.
				if err = h.Connect(conn, addr); err != nil {
					err = fmt.Errorf("failed to connect to %v:%v", addr.Network(), addr.String())
					return err
				}
				if ent, ok := natTable.Load(connKey); ok {
					pc = ent.(*natTableEntry).udpConn
					remoteAddr = ent.(*natTableEntry).remoteAddr
				}
			} else {
				_, err = conn.WriteFrom(resp, addr)
				if err != nil {
					err = errors.New(fmt.Sprintf("write dns answer failed: %v", err))
					return err
				}
				h.Close(conn)
				return nil
			}
		}

	}

	if ent, ok := natTable.Load(connKey); ok {
		pc = ent.(*natTableEntry).udpConn
		remoteAddr = ent.(*natTableEntry).remoteAddr
	} else {
		err = errors.New(fmt.Sprintf("proxy connection %v->%v does not exists", conn.LocalAddr(), addr))
		return err
	}

	var targetHost string
	if h.fakeDns != nil && h.fakeDns.IsFakeIP(addr.IP) {
		targetHost = h.fakeDns.QueryDomain(addr.IP)
	} else {
		targetHost = addr.IP.String()
	}
	dest := net.JoinHostPort(targetHost, strconv.Itoa(addr.Port))

	buf := append([]byte{0, 0, 0}, ParseAddr(dest)...)
	buf = append(buf, data[:]...)
	_, err = pc.WriteTo(buf, remoteAddr)
	if err != nil {
		err = errors.New(fmt.Sprintf("write remote failed: %v", err))
		return err
	}
	return err

}

func (h *udpHandler) Close(conn core.UDPConn) {
	conn.Close()
	connKey := getConnKey(conn)
	// Load from remoteConnMap
	if ent, ok := natTable.Load(connKey); ok {
		entry := ent.(*natTableEntry)
		entry.udpConn.Close()
		if tcp, ok := entry.tcpConn.(*net.TCPConn); ok {
			tcp.CloseRead()
			tcp.CloseWrite()
		}
		entry.tcpConn.Close()
		entry.remoteAddr = nil
	}
	natTable.Delete(connKey)
}

func getConnKey(conn core.UDPConn) string {
	return conn.LocalAddr().String()
}
