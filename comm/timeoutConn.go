package comm

import (
	"net"
	"time"
)

type TimeoutConn struct {
	net.Conn
	readTimeout time.Duration
}

// NewSmartConn 创建智能连接
func NewTimeoutConn(conn net.Conn, readTimeout time.Duration) *TimeoutConn {
	return &TimeoutConn{
		Conn:        conn,
		readTimeout: readTimeout,
	}
}

// Read 智能读取
func (c *TimeoutConn) Read(b []byte) (int, error) {
	deadline := time.Now().Add(c.readTimeout)
	c.Conn.SetReadDeadline(deadline)
	return c.Conn.Read(b)
}
