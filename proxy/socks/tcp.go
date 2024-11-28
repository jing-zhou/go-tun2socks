package socks

import (
	"io"
	"net"
	"strconv"
	"sync"

	"golang.org/x/net/proxy"

	"github.com/jing-zhou/go-tun2socks/common/dns"
	"github.com/jing-zhou/go-tun2socks/common/log"
	"github.com/jing-zhou/go-tun2socks/component/pool"
	"github.com/jing-zhou/go-tun2socks/core"
)

type tcpHandler struct {
	sync.Mutex

	proxyHost string
	proxyPort uint16

	fakeDns dns.FakeDns
}

func NewTCPHandler(proxyHost string, proxyPort uint16, fakeDns dns.FakeDns) core.TCPConnHandler {
	return &tcpHandler{
		proxyHost: proxyHost,
		proxyPort: proxyPort,
		fakeDns:   fakeDns,
	}
}

type direction byte

const (
	dirUplink direction = iota
	dirDownlink
)

type duplexConn interface {
	net.Conn
	CloseRead() error
	CloseWrite() error
}

func relayClose(src, dst net.Conn, closeErr error, closeOnce *sync.Once) {
	// interrupt the conn if the error is not nil (not EOF)
	// half close uplink direction of the TCP conn if possible
	if closeErr != nil {
		closeOnce.Do(func() {
			src.Close()
			dst.Close()
		})
		return
	}

	srcDConn, srcOk := src.(duplexConn)
	dstDConn, dstOk := dst.(duplexConn)
	if srcOk && dstOk {
		srcDConn.CloseRead()
		dstDConn.CloseWrite()
	}
}

func relayGenerator(h *tcpHandler, src, dst net.Conn, dir direction, closeOnce *sync.Once) chan bool {
	stopSig := make(chan bool)
	go func(src, dst net.Conn, dir direction, stopChan chan bool) {
		var err error
		buf := pool.NewBytes(pool.BufSize)
		defer pool.FreeBytes(buf)
		_, err = io.CopyBuffer(dst, src, buf)
		relayClose(src, dst, err, closeOnce)
		close(stopChan) // send uplink finished signal
	}(src, dst, dir, stopSig)
	return stopSig
}

func (h *tcpHandler) relay(lhs, rhs net.Conn) {
	// both uplink and downlink use the same sync.Once instance
	var closeOnce sync.Once
	uplinkSig := relayGenerator(h, lhs, rhs, dirUplink, &closeOnce)
	downlinkSig := relayGenerator(h, rhs, lhs, dirDownlink, &closeOnce)

	<-uplinkSig
	<-downlinkSig
}

func (h *tcpHandler) Handle(conn net.Conn, target *net.TCPAddr) error {
	dialer, err := proxy.SOCKS5("tcp", core.ParseTCPAddr(h.proxyHost, h.proxyPort).String(), nil, nil)
	if err != nil {
		return err
	}

	// Replace with a domain name if target address IP is a fake IP.
	var targetHost string
	if h.fakeDns != nil && h.fakeDns.IsFakeIP(target.IP) {
		targetHost = h.fakeDns.QueryDomain(target.IP)
	} else {
		targetHost = target.IP.String()
	}
	dest := net.JoinHostPort(targetHost, strconv.Itoa(target.Port))

	c, err := dialer.Dial(target.Network(), dest)
	if err != nil {
		return err
	}

	var process string = "N/A"

	// Set keepalive
	tcpKeepAlive(conn)
	tcpKeepAlive(c)

	go h.relay(conn, c)

	log.Access(process, "proxy", target.Network(), conn.LocalAddr().String(), dest)

	return nil
}
