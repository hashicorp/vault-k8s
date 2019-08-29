package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/webhook/injector"
	"log"
	"net/http"
)

var (
	certFile string
	keyFile  string
)

func main() {
	// get command line parameters
	flag.StringVar(&certFile, "tlsCertFile", "/etc/webhook/certs/cert.pem", "File containing the x509 Certificate for HTTPS.")
	flag.StringVar(&keyFile, "tlsKeyFile", "/etc/webhook/certs/key.pem", "File containing the x509 private key to --tlsCertFile.")
	flag.Parse()

	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("Filed to load key pair: %v", err)
	}

	inj := &injector.Handler{
		ImageAgent:        injector.DefaultAgentImage,
		RequireAnnotation: true,
		Log:               hclog.Default().Named("handler"),
	}

	// define http server and server handler
	mux := http.NewServeMux()
	mux.HandleFunc("/mutate", inj.Handle)

	var handler http.Handler = mux
	server := &http.Server{
		Addr:      ":443",
		Handler:   handler,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}},
	}

	inj.Log.Info(fmt.Sprintf("Listening on %q...", server.Addr))
	if err := server.ListenAndServeTLS("", ""); err != nil {
		inj.Log.Error(fmt.Sprintf("Error listening: %s", err))
		return
	}
}
