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
	udpAssocTable = &sync.Map{}
	udpConnTable  = &sync.Map{}
)

type udpConnTableEntry struct {
	udpConn net.PacketConn
}

type udpAssocTableEntry struct {
	tcpConn                 net.Conn
	resolvedRelayServerAddr *net.UDPAddr // UDP relay server addresses
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
		// Initial timeout
		c.SetDeadline(time.Now().Add(30 * time.Minute))
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
		pool.FreeBytes(buf)
		h.shutdownUDPConn(conn)
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
		_, err = conn.WriteFrom(buf[payloadPos:bytesRead], resolvedAddr)
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
			if err != nil {
				log.Warnf("fetchUDPInput: Parse port err %v", err)
				return
			}
			if portnum == uint64(dns.COMMON_DNS_PORT) {
				log.Infof("fetchUDPInput: dnsCache not nil, got COMMON_DNS_PORT, Store addrStr %v", addrStr)
				err = h.dnsCache.Store(buf[payloadPos:bytesRead])
				if err != nil {
					log.Warnf("fetchUDPInput: fail to store in DnsCache: %v", err)
				}
				return // DNS response
			}
		}
	}
}

func (h *udpHandler) startHandleUDP(conn core.UDPConn) error {
	connKey := h.getConnKey(conn)
	pc, err := net.ListenPacket("udp", "")
	if err != nil {
		return err
	}
	var storedEntry = &udpConnTableEntry{
		udpConn: pc,
	}
	log.Warnf("doUDPAssociationInternal: connKey %v entry %v", connKey, storedEntry)
	udpConnTable.Store(connKey, storedEntry)

	go h.fetchUDPInput(conn, pc)

	log.Access("N/A", "startHandleUDP", "udp", conn.LocalAddr().String(), pc.LocalAddr().String())
	return nil
}

func (h *udpHandler) Connect(conn core.UDPConn, target *net.UDPAddr) error {
	if target == nil {
		return h.doUDPAssociationAndStartUDP(conn, "")
	}

	// Replace with a domain name if target address IP is a fake IP.
	targetHost := target.IP.String()
	if h.fakeDns != nil {
		if target.Port == dns.COMMON_DNS_PORT {
			log.Infof("Connect: got general DNS packet, skip Connect()")
			return nil
		}
		if h.fakeDns.IsFakeIP(target.IP) {
			log.Infof("Connect: got FakeIP")
			targetHost = h.fakeDns.QueryDomain(target.IP)
		}
	}
	dest := net.JoinHostPort(targetHost, strconv.Itoa(target.Port))

	return h.doUDPAssociationAndStartUDP(conn, dest)

}

func (h *udpHandler) doUDPAssociation(conn core.UDPConn, dest string) error {
	var err error
	_, isExist := h.isUDPAssociationExist(conn)
	if !isExist {
		err = h.doUDPAssociationInternal(conn, dest)
		if err != nil {
			return err
		}
	}

	return err
}

func (h *udpHandler) doUDPAssociationAndStartUDP(conn core.UDPConn, dest string) error {
	err := h.doUDPAssociation(conn, dest)
	if err != nil {
		return err
	}
	return h.startHandleUDP(conn)
}

func (h *udpHandler) doUDPAssociationInternal(conn core.UDPConn, dest string) error {
	connKey := h.getConnKey(conn)
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

	var storedEntry = &udpAssocTableEntry{
		tcpConn:                 c,
		resolvedRelayServerAddr: resolvedRemoteAddr,
	}
	log.Warnf("doUDPAssociationInternal: connKey %v entry %v", connKey, storedEntry)
	udpAssocTable.Store(connKey, storedEntry)

	log.Access("N/A", "doUDPAssociationInternal", "udp", conn.LocalAddr().String(), dest)
	return nil
}

func (h *udpHandler) ReceiveTo(conn core.UDPConn, data []byte, addr *net.UDPAddr) error {
	var err error
	var pc net.PacketConn
	var remoteAddr *net.UDPAddr
	connKey := h.getConnKey(conn)
	defer func(err *error) {
		if *err != nil {
			log.Infof("ReceiveTo: Call close in defered func")
			h.Close(conn)
		}
	}(&err)

	// special case: DNS packet
	if addr.Port == dns.COMMON_DNS_PORT {
		if h.dnsCache != nil {
			log.Infof("ReceiveTo: got COMMON_DNS_PORT, fetch from dns cache")
			var answer []byte
			answer, err = h.dnsCache.Query(data)
			if err != nil {
				return err
			}
			if answer != nil {
				log.Infof("ReceiveTo: dns answer found in dnsCache, WriteFrom...")
				_, err = conn.WriteFrom(answer, addr)
				if err != nil {
					err = errors.New(fmt.Sprintf("write dns answer failed: %v", err))
					return err
				}
				h.shutdownUDPConn(conn)
				return nil
			}
		}
		if h.fakeDns != nil {
			log.Infof("ReceiveTo: intercept general DNS request, do FakeDNS query")
			var resp []byte
			resp, err = h.fakeDns.GenerateFakeResponse(data)
			if err != nil {
				log.Warnf("ReceiveTo: fakeDns GenerateFakeResponse fail %v", err)
				log.Infof("ReceiveTo: intercept general DNS request, doUDPAssociationAndStartUDP")
				if err = h.doUDPAssociationAndStartUDP(conn, addr.String()); err != nil {
					err = fmt.Errorf("failed to connect to %v:%v", addr.Network(), addr.String())
					return err
				}
				// already got UDP association, continue the following procedure
			} else {
				log.Infof("ReceiveTo: fakeDns GenerateFakeResponse success, WriteFrom addr %v", addr)
				_, err = conn.WriteFrom(resp, addr)
				if err != nil {
					err = errors.New(fmt.Sprintf("write dns answer failed: %v", err))
					return err
				}
				h.shutdownUDPConn(conn)
				return nil
			}
		}
	}

	if udpConnEnt, ok1 := udpConnTable.Load(connKey); ok1 {
		pc = udpConnEnt.(*udpConnTableEntry).udpConn
	} else {
		err = errors.New(fmt.Sprintf("udpConn %v->%v does not exist, discard the UDP packet", conn.LocalAddr(), addr))
		return err
	}

	if udpAssocEnt, ok2 := udpAssocTable.Load(connKey); ok2 {
		remoteAddr = udpAssocEnt.(*udpAssocTableEntry).resolvedRelayServerAddr
	} else {
		err = errors.New(fmt.Sprintf("udpConn %v->%v association not exist, discard", conn.LocalAddr(), addr))
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

// Close do a full close
func (h *udpHandler) Close(conn core.UDPConn) {
	h.shutdownUDPConn(conn)
	h.invalidateUDPAssociation(conn)
}

func (h *udpHandler) shutdownUDPConn(conn core.UDPConn) {
	connKey := h.getConnKey(conn)
	conn.Close()
	if ent, ok := udpConnTable.Load(connKey); ok {
		entry := ent.(*udpConnTableEntry)
		entry.udpConn.Close()
	}
	udpConnTable.Delete(connKey)
}

func (h *udpHandler) invalidateUDPAssociation(conn core.UDPConn) {
	connKey := h.getConnKey(conn)
	if ent, ok := udpAssocTable.Load(connKey); ok {
		entry := ent.(*udpAssocTableEntry)
		if tcp, ok := entry.tcpConn.(*net.TCPConn); ok {
			tcp.CloseRead()
			tcp.CloseWrite()
		}
		entry.tcpConn.Close()
		entry.resolvedRelayServerAddr = nil
	}
	udpAssocTable.Delete(connKey)
}

func (h *udpHandler) isUDPAssociationExist(conn core.UDPConn) (entry *udpAssocTableEntry, ok bool) {
	connKey := h.getConnKey(conn)
	ent, ok := udpAssocTable.Load(connKey)
	if ok {
		// each success check means we have valid UDP packet, we extend the udpAssocTable timeout
		c := ent.(*udpAssocTableEntry).tcpConn
		err := c.SetDeadline(time.Now().Add(5 * time.Second))
		if err != nil {
			// seems to be invalid this time
			return nil, false
		}
		return ent.(*udpAssocTableEntry), ok
	} else {
		return nil, ok
	}
}

func (h *udpHandler) getConnKey(conn core.UDPConn) string {
	return conn.LocalAddr().String()
}
