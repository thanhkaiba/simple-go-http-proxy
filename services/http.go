package services

import (
	"fmt"
	"io"
	logger "log"
	"net"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/snail007/goproxy/utils"

	"golang.org/x/crypto/ssh"
)

type HTTP struct {
	outPool        utils.OutConn
	cfg            HTTPArgs
	sshClient      ssh.Client
	lockChn        chan bool
	domainResolver utils.DomainResolver
	isStop         bool
	serverChannels []*utils.ServerChannel
	userConns      utils.ConcurrentMap
	log            *logger.Logger
}

func NewHTTP() *HTTP {
	return &HTTP{
		outPool:        utils.OutConn{},
		cfg:            HTTPArgs{},
		lockChn:        make(chan bool, 1),
		isStop:         false,
		serverChannels: []*utils.ServerChannel{},
		userConns:      utils.NewConcurrentMap(),
	}
}

func (s *HTTP) StopService() {
	defer func() {
		e := recover()
		if e != nil {
			s.log.Printf("stop http(s) service crashed,%s", e)
		} else {
			s.log.Printf("service http(s) stoped")
		}
	}()
	s.isStop = true

	for _, sc := range s.serverChannels {
		if sc.Listener != nil && sc.Listener != nil {
			(*sc.Listener).Close()
		}
		if sc.UDPListener != nil {
			(sc.UDPListener).Close()
		}
	}
}
func (s *HTTP) Start(args HTTPArgs, log *logger.Logger) (err error) {
	s.log = log
	s.cfg = args

	if s.cfg.Parent != "" {
		s.log.Printf("use %s parent %s", s.cfg.ParentType, s.cfg.Parent)
		s.InitOutConnPool()
	}

	for _, addr := range strings.Split(s.cfg.Local, ",") {
		if addr != "" {
			host, port, _ := net.SplitHostPort(addr)
			p, _ := strconv.Atoi(port)
			sc := utils.NewServerChannel(host, p, s.log)
			err = sc.ListenTCP(s.callback)
			if err != nil {
				return
			}
			s.log.Printf("%s http(s) proxy", (*sc.Listener).Addr())
			s.serverChannels = append(s.serverChannels, &sc)
		}
	}
	return
}

func (s *HTTP) Clean() {
	s.StopService()
}
func (s *HTTP) callback(inConn net.Conn) {
	defer func() {
		if err := recover(); err != nil {
			s.log.Printf("http(s) conn handler crashed with err : %s \nstack: %s", err, string(debug.Stack()))
		}
	}()

	var err interface{}
	var req utils.HTTPRequest
	req, err = utils.NewHTTPRequest(&inConn, 4096, s.log)
	if err != nil {
		if err != io.EOF {
			s.log.Printf("decoder error , from %s, ERR:%s", inConn.RemoteAddr(), err)
		}
		utils.CloseConn(&inConn)
		return
	}

	err = s.OutToTCP(true, &inConn, &req)
	if err != nil {
		s.log.Printf("connect to %s parent %s fail", s.cfg.ParentType, s.cfg.Parent)
		utils.CloseConn(&inConn)
	}
}
func (s *HTTP) OutToTCP(useProxy bool, inConn *net.Conn, req *utils.HTTPRequest) (err interface{}) {
	inAddr := (*inConn).RemoteAddr().String()
	inLocalAddr := (*inConn).LocalAddr().String()
	//防止死循环
	if s.IsDeadLoop(inLocalAddr, req.Host) {
		utils.CloseConn(inConn)
		err = fmt.Errorf("dead loop detected , %s", req.Host)
		return
	}
	var outConn net.Conn
	tryCount := 0
	maxTryCount := 5
	for {
		if s.isStop {
			return
		}
		if useProxy {
			outConn, err = s.outPool.Get()
		}
		tryCount++
		if err == nil || tryCount > maxTryCount {
			break
		} else {
			s.log.Printf("connect to %s , err:%s,retrying...", s.cfg.Parent, err)
			time.Sleep(time.Second * 2)
		}
	}
	if err != nil {
		s.log.Printf("connect to %s , err:%s", s.cfg.Parent, err)
		utils.CloseConn(inConn)
		return
	}

	outAddr := outConn.RemoteAddr().String()
	//outLocalAddr := outConn.LocalAddr().String()
	//https或者http,上级是代理,proxy需要转发
	outConn.SetDeadline(time.Now().Add(time.Millisecond * time.Duration(s.cfg.Timeout)))
	//直连目标或上级非代理,清理HTTP头部的代理头信息
	if !useProxy || s.cfg.ParentType == "ssh" {
		_, err = outConn.Write(utils.RemoveProxyHeaders(req.HeadBuf))
	} else {
		_, err = outConn.Write(req.HeadBuf)
	}
	outConn.SetDeadline(time.Time{})
	if err != nil {
		s.log.Printf("write to %s , err:%s", s.cfg.Parent, err)
		utils.CloseConn(inConn)
		return
	}

	utils.IoBind((*inConn), outConn, func(err interface{}) {
		s.log.Printf("conn %s - %s released [%s]", inAddr, outAddr, req.Host)
		s.userConns.Remove(inAddr)
	}, s.log)
	s.log.Printf("conn %s - %s connected [%s]", inAddr, outAddr, req.Host)
	if c, ok := s.userConns.Get(inAddr); ok {
		(*c.(*net.Conn)).Close()
	}
	s.userConns.Set(inAddr, inConn)
	return
}

func (s *HTTP) InitOutConnPool() {
	s.outPool = utils.NewOutConn(
		s.cfg.CheckParentInterval,
		s.cfg.Parent,
		s.cfg.Timeout,
	)
}

func (s *HTTP) IsDeadLoop(inLocalAddr string, host string) bool {
	inIP, inPort, err := net.SplitHostPort(inLocalAddr)
	if err != nil {
		return false
	}
	outDomain, outPort, err := net.SplitHostPort(host)
	if err != nil {
		return false
	}
	if inPort == outPort {
		var outIPs []net.IP
		outIPs, err = net.LookupIP(outDomain)
		if err == nil {
			for _, ip := range outIPs {
				if ip.String() == inIP {
					return true
				}
			}
		}
		interfaceIPs, err := utils.GetAllInterfaceAddr()
		if err == nil {
			for _, localIP := range interfaceIPs {
				for _, outIP := range outIPs {
					if localIP.Equal(outIP) {
						return true
					}
				}
			}
		}
	}
	return false
}
