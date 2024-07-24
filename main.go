package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/snail007/goproxy/services"
)

func main() {
	proxy := services.NewHTTP()
	httpArgs := services.HTTPArgs{}
	httpArgs.Parent = "127.0.0.1:8282"

	httpArgs.ParentType = "tcp"
	httpArgs.Timeout = 2000
	httpArgs.HTTPTimeout = 3000
	httpArgs.CheckParentInterval = 3
	httpArgs.Local = "127.0.0.1:8283"
	proxy.Start(httpArgs, log.New(os.Stdout, "", 0))
	Clean(proxy)
}
func Clean(s *services.HTTP) {
	signalChan := make(chan os.Signal, 1)
	cleanupDone := make(chan bool)
	signal.Notify(signalChan,
		os.Interrupt,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	go func() {
		for _ = range signalChan {
			log.Println("Received an interrupt, stopping services...")
			if s != nil {
				(*s).Clean()
			}
			cleanupDone <- true
		}
	}()
	<-cleanupDone
}
