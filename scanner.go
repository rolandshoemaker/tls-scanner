package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var suiteToString = map[uint16]string{
	0x0005: "RSA WITH RC4 128 SHA",
	0x000a: "RSA WITH 3DES EDE CBC SHA",
	0x002f: "RSA WITH AES 128 CBC SHA",
	0x0035: "RSA WITH AES 256 CBC SHA",
	0xc007: "ECDHE ECDSA WITH RC4 128 SHA",
	0xc009: "ECDHE ECDSA WITH AES 128 CBC SHA",
	0xc00a: "ECDHE ECDSA WITH AES 256 CBC SHA",
	0xc011: "ECDHE RSA WITH RC4 128 SHA",
	0xc012: "ECDHE RSA WITH 3DES EDE CBC SHA",
	0xc013: "ECDHE RSA WITH AES 128 CBC SHA",
	0xc014: "ECDHE RSA WITH AES 256 CBC SHA",
	0xc02f: "ECDHE RSA WITH AES 128 GCM SHA256",
	0xc02b: "ECDHE ECDSA WITH AES 128 GCM SHA256",
	0xc030: "ECDHE RSA WITH AES 256 GCM SHA384",
	0xc02c: "ECDHE ECDSA WITH AES 256 GCM SHA384",
}

type cert struct {
	Names     []string
	Subject   string
	Issuer    string
	Skid      string
	Akid      string
	NotBefore time.Time
	NotAfter  time.Time
}

type result struct {
	Name string

	Started  time.Time
	Finished time.Time

	Error                 string
	TimedOut              bool
	NXDomain              bool
	Available             bool
	TLSError              bool
	MiscInvalidCert       bool
	Expired               bool
	IncorrectChain        bool
	IncorrectIntermediate bool
	WrongNames            bool
	SelfSigned            bool

	SentCertificates []cert
	CipherSuite      string
	StapledOCSP      bool
	ServedSCT        bool
}

type scanner struct {
	workers int

	names   chan string
	results chan result

	dialerTimeout time.Duration

	resultsFile *os.File
}

func extend(s, c string, a []string) string {
	if len(a) == 0 {
		return s
	}
	return s + fmt.Sprintf(" %s=[%s]", c, strings.Join(a, ", "))
}

func subjectToString(subject *pkix.Name) string {
	s := fmt.Sprintf(
		"cn=[%s]",
		subject.CommonName,
	)
	s = extend(s, "o", subject.Organization)
	s = extend(s, "ou", subject.OrganizationalUnit)
	s = extend(s, "st", subject.Province)
	s = extend(s, "l", subject.Locality)
	s = extend(s, "c", subject.Country)
	return s
}

func (s *scanner) processName(name string) (r result) {
	r.Started = time.Now()
	defer func() {
		r.Finished = time.Now()
	}()
	r.Name = name
	// XXX: dialer/TLS config should accept all cipher suites instead of
	// the default set to catch everything
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: s.dialerTimeout},
		"tcp", fmt.Sprintf("%s:443", name),
		&tls.Config{
			PreferServerCipherSuites: true,
			InsecureSkipVerify:       true,
		},
	)
	if err != nil {
		r.Error = err.Error()
		if netErr, ok := err.(*net.OpError); ok {
			if netErr.Timeout() || netErr.Temporary() {
				r.TimedOut = true
			}
			if dnsErr, ok := netErr.Err.(*net.DNSError); ok {
				if dnsErr.Timeout() || dnsErr.Temporary() {
					r.TimedOut = true
				} else {
					r.NXDomain = true
				}
			}
			return
		}
		r.Available = true
		if strings.HasPrefix(err.Error(), "tls:") || err.Error() == "EOF" {
			r.TLSError = true
			return
		}
		r.MiscInvalidCert = true
		return
	}

	r.Available = true
	state := conn.ConnectionState()
	conn.Close()
	r.CipherSuite = suiteToString[state.CipherSuite]
	if len(state.PeerCertificates) == 0 {
		r.IncorrectChain = true
		return
	}
	for _, c := range state.PeerCertificates {
		r.SentCertificates = append(r.SentCertificates, cert{
			Names:     c.DNSNames,
			Subject:   subjectToString(&c.Subject),
			Issuer:    subjectToString(&c.Issuer),
			Skid:      fmt.Sprintf("%x", c.SubjectKeyId),
			Akid:      fmt.Sprintf("%x", c.AuthorityKeyId),
			NotBefore: c.NotBefore,
			NotAfter:  c.NotAfter,
		})
	}

	if len(state.OCSPResponse) != 0 {
		r.StapledOCSP = true
	}
	if len(state.SignedCertificateTimestamps) != 0 {
		r.ServedSCT = true
	}

	// verify certificate
	intermediates := x509.NewCertPool()
	for _, i := range state.PeerCertificates[1:] {
		intermediates.AddCert(i)
	}
	_, err = state.PeerCertificates[0].Verify(x509.VerifyOptions{
		DNSName:       name,
		Intermediates: intermediates,
	})
	if _, ok := err.(x509.UnknownAuthorityError); ok {
		r.IncorrectChain = true
		return
	}
	if _, ok := err.(x509.HostnameError); ok {
		r.WrongNames = true
		return
	}
	if invErr, ok := err.(x509.CertificateInvalidError); ok {
		if invErr.Reason == x509.Expired {
			r.Expired = true
			return
		} else if invErr.Reason == x509.NotAuthorizedToSign {
			r.SelfSigned = true
			return
		}
	}

	return
}

func (s *scanner) run() {
	done := make(chan struct{}, 1)
	go func() {
		for r := range s.results {
			err := s.writeResult(r)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to write result to '%s': %s\n", s.resultsFile.Name(), err)
				os.Exit(1)
			}
		}
		done <- struct{}{}
	}()
	wg := new(sync.WaitGroup)
	for i := 0; i < s.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := range s.names {
				s.results <- s.processName(n)
			}
		}()
	}
	wg.Wait()
	close(s.results)
	<-done
}

func (s *scanner) writeResult(r result) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = s.resultsFile.Write(append(data, []byte("\n")...))
	return err
}

func main() {
	workers := flag.Int("workers", 1, "")
	namesPath := flag.String("names", "names.txt", "")
	skip := flag.Int("skip", 0, "")
	max := flag.Int("max", 0, "")
	resultsPath := flag.String("results", "results.json", "")
	flag.Parse()

	timeout := time.Second * 10

	names := make(chan string, 1000)
	namesFile, err := os.OpenFile(*namesPath, os.O_RDONLY, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open names file '%s': %s\n", *namesPath, err)
		os.Exit(1)
	}
	go func() {
		defer namesFile.Close()
		lineReader := bufio.NewScanner(namesFile)
		i := 1
		a := 1
		for lineReader.Scan() {
			if i > *skip {
				names <- lineReader.Text()
				a++
				if *max > 0 && a >= *max {
					break
				}
			}
			i++
		}
		if err := lineReader.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read names file '%s': %s\n", *namesPath, err)
			os.Exit(1)
		}
		close(names)
	}()

	resultsFile, err := os.OpenFile(*resultsPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open results file '%s': %s\n", *resultsPath, err)
		os.Exit(1)
	}
	defer resultsFile.Close()

	s := &scanner{
		workers:       *workers,
		names:         names,
		results:       make(chan result, len(names)),
		dialerTimeout: timeout,
		resultsFile:   resultsFile,
	}
	s.run()
}
