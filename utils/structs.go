package utils

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	logger "log"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/snail007/goproxy/utils/sni"

	"github.com/golang/snappy"
	"github.com/miekg/dns"
)

type BasicAuth struct {
	data        ConcurrentMap
	authURL     string
	authOkCode  int
	authTimeout int
	authRetry   int
	dns         *DomainResolver
	log         *logger.Logger
}

func NewBasicAuth(dns *DomainResolver, log *logger.Logger) BasicAuth {
	return BasicAuth{
		data: NewConcurrentMap(),
		dns:  dns,
		log:  log,
	}
}
func (ba *BasicAuth) SetAuthURL(URL string, code, timeout, retry int) {
	ba.authURL = URL
	ba.authOkCode = code
	ba.authTimeout = timeout
	ba.authRetry = retry
}
func (ba *BasicAuth) AddFromFile(file string) (n int, err error) {
	_content, err := ioutil.ReadFile(file)
	if err != nil {
		return
	}
	userpassArr := strings.Split(strings.Replace(string(_content), "\r", "", -1), "\n")
	for _, userpass := range userpassArr {
		if strings.HasPrefix("#", userpass) {
			continue
		}
		u := strings.Split(strings.Trim(userpass, " "), ":")
		if len(u) == 2 {
			ba.data.Set(u[0], u[1])
			n++
		}
	}
	return
}

func (ba *BasicAuth) Add(userpassArr []string) (n int) {
	for _, userpass := range userpassArr {
		u := strings.Split(userpass, ":")
		if len(u) == 2 {
			ba.data.Set(u[0], u[1])
			n++
		}
	}
	return
}
func (ba *BasicAuth) CheckUserPass(user, pass, ip, target string) (ok bool) {

	return ba.Check(user+":"+pass, ip, target)
}
func (ba *BasicAuth) Check(userpass string, ip, target string) (ok bool) {
	u := strings.Split(strings.Trim(userpass, " "), ":")
	if len(u) == 2 {
		if p, _ok := ba.data.Get(u[0]); _ok {
			return p.(string) == u[1]
		}
		if ba.authURL != "" {
			err := ba.checkFromURL(userpass, ip, target)
			if err == nil {
				return true
			}
			ba.log.Printf("%s", err)
		}
		return false
	}
	return
}
func (ba *BasicAuth) checkFromURL(userpass, ip, target string) (err error) {
	u := strings.Split(strings.Trim(userpass, " "), ":")
	if len(u) != 2 {
		return
	}

	URL := ba.authURL
	if strings.Contains(URL, "?") {
		URL += "&"
	} else {
		URL += "?"
	}
	URL += fmt.Sprintf("user=%s&pass=%s&ip=%s&target=%s", u[0], u[1], ip, url.QueryEscape(target))
	getURL := URL
	var domain string
	if ba.dns != nil {
		_url, _ := url.Parse(ba.authURL)
		domain = _url.Host
		domainIP := ba.dns.MustResolve(domain)
		getURL = strings.Replace(URL, domain, domainIP, 1)
	}
	var code int
	var tryCount = 0
	var body []byte
	for tryCount <= ba.authRetry {
		body, code, err = HttpGet(getURL, ba.authTimeout, domain)
		if err == nil && code == ba.authOkCode {
			break
		} else if err != nil {
			err = fmt.Errorf("auth fail from url %s,resonse err:%s , %s", URL, err, ip)
		} else {
			if len(body) > 0 {
				err = fmt.Errorf(string(body[0:100]))
			} else {
				err = fmt.Errorf("token error")
			}
			b := string(body)
			if len(b) > 50 {
				b = b[:50]
			}
			err = fmt.Errorf("auth fail from url %s,resonse code: %d, except: %d , %s , %s", URL, code, ba.authOkCode, ip, b)
		}
		if err != nil && tryCount < ba.authRetry {
			ba.log.Print(err)
			time.Sleep(time.Second * 2)
		}
		tryCount++
	}
	if err != nil {
		return
	}
	//log.Printf("auth success from auth url, %s", ip)
	return
}

func (ba *BasicAuth) Total() (n int) {
	n = ba.data.Count()
	return
}

type HTTPRequest struct {
	HeadBuf   []byte
	conn      *net.Conn
	Host      string
	Method    string
	URL       string
	hostOrURL string
	log       *logger.Logger
}

func NewHTTPRequest(inConn *net.Conn, bufSize int, log *logger.Logger, header ...[]byte) (req HTTPRequest, err error) {
	buf := make([]byte, bufSize)
	n := 0
	req = HTTPRequest{
		conn: inConn,
		log:  log,
	}
	if header != nil && len(header) == 1 && len(header[0]) > 1 {
		buf = header[0]
		n = len(header[0])
	} else {
		n, err = (*inConn).Read(buf[:])
		if err != nil {
			if err != io.EOF {
				err = fmt.Errorf("http decoder read err:%s", err)
			}
			CloseConn(inConn)
			return
		}
	}

	req.HeadBuf = buf[:n]
	//fmt.Println(string(req.HeadBuf))
	//try sni
	serverName, err0 := sni.ServerNameFromBytes(req.HeadBuf)
	if err0 == nil {
		//sni success
		req.Method = "SNI"
		req.hostOrURL = "https://" + serverName + ":443"
	} else {
		//sni fail , try http
		index := bytes.IndexByte(req.HeadBuf, '\n')
		if index == -1 {
			err = fmt.Errorf("http decoder data line err:%s", SubStr(string(req.HeadBuf), 0, 50))
			CloseConn(inConn)
			return
		}
		fmt.Sscanf(string(req.HeadBuf[:index]), "%s%s", &req.Method, &req.hostOrURL)
	}
	if req.Method == "" || req.hostOrURL == "" {
		err = fmt.Errorf("http decoder data err:%s", SubStr(string(req.HeadBuf), 0, 50))
		CloseConn(inConn)
		return
	}
	req.Method = strings.ToUpper(req.Method)
	log.Printf("%s:%s", req.Method, req.hostOrURL)

	if req.IsHTTPS() {
		err = req.HTTPS()
	} else {
		err = req.HTTP()
	}
	return
}
func (req *HTTPRequest) HTTP() (err error) {
	req.URL = req.getHTTPURL()
	var u *url.URL
	u, err = url.Parse(req.URL)
	if err != nil {
		return
	}
	req.Host = u.Host
	req.addPortIfNot()
	return
}
func (req *HTTPRequest) HTTPS() (err error) {
	req.Host = req.hostOrURL
	req.addPortIfNot()
	return
}
func (req *HTTPRequest) HTTPSReply() (err error) {
	_, err = fmt.Fprint(*req.conn, "HTTP/1.1 200 Connection established\r\n\r\n")
	return
}
func (req *HTTPRequest) IsHTTPS() bool {
	return req.Method == "CONNECT"
}

func (req *HTTPRequest) GetAuthDataStr() (basicInfo string, err error) {
	// log.Printf("request :%s", string(req.HeadBuf))
	authorization := req.getHeader("Proxy-Authorization")

	authorization = strings.Trim(authorization, " \r\n\t")
	if authorization == "" {
		fmt.Fprintf((*req.conn), "HTTP/1.1 %s Unauthorized\r\nWWW-Authenticate: Basic realm=\"\"\r\n\r\nUnauthorized", "407")
		CloseConn(req.conn)
		err = errors.New("require auth header data")
		return
	}
	//log.Printf("Authorization:%authorization = req.getHeader("Authorization")
	basic := strings.Fields(authorization)
	if len(basic) != 2 {
		err = fmt.Errorf("authorization data error,ERR:%s", authorization)
		CloseConn(req.conn)
		return
	}
	user, err := base64.StdEncoding.DecodeString(basic[1])
	if err != nil {
		err = fmt.Errorf("authorization data parse error,ERR:%s", err)
		CloseConn(req.conn)
		return
	}
	basicInfo = string(user)
	return
}

func (req *HTTPRequest) getHTTPURL() (URL string) {
	if !strings.HasPrefix(req.hostOrURL, "/") {
		return req.hostOrURL
	}
	_host := req.getHeader("host")
	if _host == "" {
		return
	}
	URL = fmt.Sprintf("http://%s%s", _host, req.hostOrURL)
	return
}
func (req *HTTPRequest) getHeader(key string) (val string) {
	key = strings.ToUpper(key)
	lines := strings.Split(string(req.HeadBuf), "\r\n")
	//log.Println(lines)
	for _, line := range lines {
		hline := strings.SplitN(strings.Trim(line, "\r\n "), ":", 2)
		if len(hline) == 2 {
			k := strings.ToUpper(strings.Trim(hline[0], " "))
			v := strings.Trim(hline[1], " ")
			if key == k {
				val = v
				return
			}
		}
	}
	return
}

func (req *HTTPRequest) addPortIfNot() (newHost string) {
	//newHost = req.Host
	port := "80"
	if req.IsHTTPS() {
		port = "443"
	}
	if (!strings.HasPrefix(req.Host, "[") && strings.Index(req.Host, ":") == -1) || (strings.HasPrefix(req.Host, "[") && strings.HasSuffix(req.Host, "]")) {
		//newHost = req.Host + ":" + port
		//req.headBuf = []byte(strings.Replace(string(req.headBuf), req.Host, newHost, 1))
		req.Host = req.Host + ":" + port
	}
	return
}

type OutConn struct {
	dur      int
	keyBytes []byte
	address  string
	timeout  int
}

func NewOutConn(dur int, address string, timeout int) (op OutConn) {
	return OutConn{
		dur:     dur,
		address: address,
		timeout: timeout,
	}
}
func (op *OutConn) Get() (conn net.Conn, err error) {
	conn, err = ConnectHost(op.address, op.timeout)
	return
}

type ConnManager struct {
	pool ConcurrentMap
	l    *sync.Mutex
	log  *logger.Logger
}

func NewConnManager(log *logger.Logger) ConnManager {
	cm := ConnManager{
		pool: NewConcurrentMap(),
		l:    &sync.Mutex{},
		log:  log,
	}
	return cm
}
func (cm *ConnManager) Add(key, ID string, conn *net.Conn) {
	cm.pool.Upsert(key, nil, func(exist bool, valueInMap interface{}, newValue interface{}) interface{} {
		var conns ConcurrentMap
		if !exist {
			conns = NewConcurrentMap()
		} else {
			conns = valueInMap.(ConcurrentMap)
		}
		if conns.Has(ID) {
			v, _ := conns.Get(ID)
			(*v.(*net.Conn)).Close()
		}
		conns.Set(ID, conn)
		cm.log.Printf("%s conn added", key)
		return conns
	})
}
func (cm *ConnManager) Remove(key string) {
	var conns ConcurrentMap
	if v, ok := cm.pool.Get(key); ok {
		conns = v.(ConcurrentMap)
		conns.IterCb(func(key string, v interface{}) {
			CloseConn(v.(*net.Conn))
		})
		cm.log.Printf("%s conns closed", key)
	}
	cm.pool.Remove(key)
}
func (cm *ConnManager) RemoveOne(key string, ID string) {
	defer cm.l.Unlock()
	cm.l.Lock()
	var conns ConcurrentMap
	if v, ok := cm.pool.Get(key); ok {
		conns = v.(ConcurrentMap)
		if conns.Has(ID) {
			v, _ := conns.Get(ID)
			(*v.(*net.Conn)).Close()
			conns.Remove(ID)
			cm.pool.Set(key, conns)
			cm.log.Printf("%s %s conn closed", key, ID)
		}
	}
}
func (cm *ConnManager) RemoveAll() {
	for _, k := range cm.pool.Keys() {
		cm.Remove(k)
	}
}

type ClientKeyRouter struct {
	keyChan chan string
	ctrl    *ConcurrentMap
	lock    *sync.Mutex
}

func NewClientKeyRouter(ctrl *ConcurrentMap, size int) ClientKeyRouter {
	return ClientKeyRouter{
		keyChan: make(chan string, size),
		ctrl:    ctrl,
		lock:    &sync.Mutex{},
	}
}
func (c *ClientKeyRouter) GetKey() string {
	defer c.lock.Unlock()
	c.lock.Lock()
	if len(c.keyChan) == 0 {
	EXIT:
		for _, k := range c.ctrl.Keys() {
			select {
			case c.keyChan <- k:
			default:
				goto EXIT
			}
		}
	}
	for {
		if len(c.keyChan) == 0 {
			return "*"
		}
		select {
		case key := <-c.keyChan:
			if c.ctrl.Has(key) {
				return key
			}
		default:
			return "*"
		}
	}

}

type DomainResolver struct {
	ttl         int
	dnsAddrress string
	data        ConcurrentMap
	log         *logger.Logger
}
type DomainResolverItem struct {
	ip        string
	domain    string
	expiredAt int64
}

func NewDomainResolver(dnsAddrress string, ttl int, log *logger.Logger) DomainResolver {
	return DomainResolver{
		ttl:         ttl,
		dnsAddrress: dnsAddrress,
		data:        NewConcurrentMap(),
		log:         log,
	}
}
func (a *DomainResolver) MustResolve(address string) (ip string) {
	ip, _ = a.Resolve(address)
	return
}
func (a *DomainResolver) Resolve(address string) (ip string, err error) {
	domain := address
	port := ""
	fromCache := "false"
	defer func() {
		if port != "" {
			ip = net.JoinHostPort(ip, port)
		}
		a.log.Printf("dns:%s->%s,cache:%s", address, ip, fromCache)
		//a.PrintData()
	}()
	if strings.Contains(domain, ":") {
		domain, port, err = net.SplitHostPort(domain)
		if err != nil {
			return
		}
	}
	if net.ParseIP(domain) != nil {
		ip = domain
		fromCache = "ip ignore"
		return
	}
	item, ok := a.data.Get(domain)
	if ok {
		//log.Println("find ", domain)
		if (*item.(*DomainResolverItem)).expiredAt > time.Now().Unix() {
			ip = (*item.(*DomainResolverItem)).ip
			fromCache = "true"
			//log.Println("from cache ", domain)
			return
		}
	} else {
		item = &DomainResolverItem{
			domain: domain,
		}

	}
	c := new(dns.Client)
	c.DialTimeout = time.Millisecond * 5000
	c.ReadTimeout = time.Millisecond * 5000
	c.WriteTimeout = time.Millisecond * 5000
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m.RecursionDesired = true
	r, _, err := c.Exchange(m, a.dnsAddrress)
	if r == nil {
		return
	}
	if r.Rcode != dns.RcodeSuccess {
		err = fmt.Errorf(" *** invalid answer name %s after A query for %s", domain, a.dnsAddrress)
		return
	}
	for _, answer := range r.Answer {
		if answer.Header().Rrtype == dns.TypeA {
			info := strings.Fields(answer.String())
			if len(info) >= 5 {
				ip = info[4]
				_item := item.(*DomainResolverItem)
				(*_item).expiredAt = time.Now().Unix() + int64(a.ttl)
				(*_item).ip = ip
				a.data.Set(domain, item)
				return
			}
		}
	}
	return
}
func (a *DomainResolver) PrintData() {
	for k, item := range a.data.Items() {
		d := item.(*DomainResolverItem)
		a.log.Printf("%s:ip[%s],domain[%s],expired at[%d]\n", k, (*d).ip, (*d).domain, (*d).expiredAt)
	}
}
func NewCompStream(conn net.Conn) *CompStream {
	c := new(CompStream)
	c.conn = conn
	c.w = snappy.NewBufferedWriter(conn)
	c.r = snappy.NewReader(conn)
	return c
}
func NewCompConn(conn net.Conn) net.Conn {
	c := CompStream{}
	c.conn = conn
	c.w = snappy.NewBufferedWriter(conn)
	c.r = snappy.NewReader(conn)
	return &c
}

type CompStream struct {
	net.Conn
	conn net.Conn
	w    *snappy.Writer
	r    *snappy.Reader
}

func (c *CompStream) Read(p []byte) (n int, err error) {
	return c.r.Read(p)
}

func (c *CompStream) Write(p []byte) (n int, err error) {
	n, err = c.w.Write(p)
	err = c.w.Flush()
	return n, err
}

func (c *CompStream) Close() error {
	return c.conn.Close()
}
func (c *CompStream) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}
func (c *CompStream) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}
func (c *CompStream) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}
func (c *CompStream) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}
func (c *CompStream) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

type BufferedConn struct {
	r        *bufio.Reader
	net.Conn // So that most methods are embedded
}

func NewBufferedConn(c net.Conn) BufferedConn {
	return BufferedConn{bufio.NewReader(c), c}
}

func NewBufferedConnSize(c net.Conn, n int) BufferedConn {
	return BufferedConn{bufio.NewReaderSize(c, n), c}
}

func (b BufferedConn) Peek(n int) ([]byte, error) {
	return b.r.Peek(n)
}

func (b BufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}
func (b BufferedConn) ReadByte() (byte, error) {
	return b.r.ReadByte()
}
func (b BufferedConn) UnreadByte() error {
	return b.r.UnreadByte()
}
func (b BufferedConn) Buffered() int {
	return b.r.Buffered()
}
