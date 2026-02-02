package comm

import (
	"net"
	"time"
)

type TimeoutConn struct {
	net.Conn
	readTimeout  time.Duration
	writeTimeout time.Duration
}

// NewSmartConn 创建智能连接
func NewTimeoutConn(conn net.Conn, readTimeout, writeTimeout time.Duration) *TimeoutConn {
	return &TimeoutConn{
		Conn:         conn,
		readTimeout:  readTimeout,
		writeTimeout: writeTimeout,
	}
}

// Read 智能读取
func (c *TimeoutConn) Read(b []byte) (int, error) {
	deadline := time.Now().Add(c.readTimeout)
	c.Conn.SetReadDeadline(deadline)
	return c.Conn.Read(b)
}

// Write 智能写入
func (c *TimeoutConn) Write(b []byte) (int, error) {
	deadline := time.Now().Add(c.writeTimeout)
	c.Conn.SetWriteDeadline(deadline)
	return c.Conn.Write(b)
}
