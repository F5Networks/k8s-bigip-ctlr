// go
package controller

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type fakeWebHook struct {
	address  string
	Server   *http.Server
	DialFunc func(network, addr string, config *tls.Config) (*tls.Conn, error)
}

func (w fakeWebHook) IsWebhookServerRunning() bool {
	if w.DialFunc != nil {
		_, err := w.DialFunc("tcp", w.address, &tls.Config{InsecureSkipVerify: true})
		return err == nil
	}
	return false
}

func (w fakeWebHook) GetWebhookServer() *http.Server {
	return w.Server
}

//func TestWebhook(t *testing.T) {
//	RegisterFailHandler(Fail)
//	RunSpecs(t, "Controller Suite")
//}

var _ = Describe("webHook", func() {
	Context("IsWebhookServerRunning", func() {
		It("returns true when server is reachable", func() {
			w := fakeWebHook{
				address: "localhost:443",
				DialFunc: func(network, addr string, config *tls.Config) (*tls.Conn, error) {
					return &tls.Conn{}, nil
				},
			}
			Expect(w.IsWebhookServerRunning()).To(BeTrue())
		})

		It("returns false when server is not reachable", func() {
			w := fakeWebHook{
				address: "localhost:443",
				DialFunc: func(network, addr string, config *tls.Config) (*tls.Conn, error) {
					return nil, errors.New("connection failed")
				},
			}
			Expect(w.IsWebhookServerRunning()).To(BeFalse())
		})
	})

	Context("GetWebhookServer", func() {
		It("returns the http.Server instance", func() {
			server := &http.Server{}
			w := fakeWebHook{Server: server}
			Expect(w.GetWebhookServer()).To(Equal(server))
		})
	})
})

var _ = Describe("loadAndValidateTLSCertificate", func() {
	var tmpDir string

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "tls-ut-*")
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		_ = os.RemoveAll(tmpDir)
	})

	write := func(certPEM, keyPEM []byte) (string, string) {
		certPath := filepath.Join(tmpDir, "tls.crt")
		keyPath := filepath.Join(tmpDir, "tls.key")
		Expect(os.WriteFile(certPath, certPEM, 0o600)).To(Succeed())
		Expect(os.WriteFile(keyPath, keyPEM, 0o600)).To(Succeed())
		return certPath, keyPath
	}

	It("succeeds for a currently valid certificate", func() {
		notBefore := time.Now().Add(-1 * time.Hour)
		notAfter := time.Now().Add(1 * time.Hour)
		certPEM, keyPEM := genSelfSignedCert("localhost", notBefore, notAfter)

		certPath, keyPath := write(certPEM, keyPEM)
		cert, err := loadAndValidateTLSCertificate(certPath, keyPath)
		Expect(err).ToNot(HaveOccurred())
		Expect(cert.Certificate).ToNot(BeEmpty())
		Expect(cert.PrivateKey).ToNot(BeNil())
	})

	It("fails for an expired certificate", func() {
		notBefore := time.Now().Add(-2 * time.Hour)
		notAfter := time.Now().Add(-1 * time.Hour)
		certPEM, keyPEM := genSelfSignedCert("localhost", notBefore, notAfter)

		certPath, keyPath := write(certPEM, keyPEM)
		_, err := loadAndValidateTLSCertificate(certPath, keyPath)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("expired"))
	})

	It("fails for a not-yet-valid certificate", func() {
		notBefore := time.Now().Add(1 * time.Hour)
		notAfter := time.Now().Add(2 * time.Hour)
		certPEM, keyPEM := genSelfSignedCert("localhost", notBefore, notAfter)

		certPath, keyPath := write(certPEM, keyPEM)
		_, err := loadAndValidateTLSCertificate(certPath, keyPath)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("not valid yet"))
	})

	It("fails for invalid PEM", func() {
		// generate valid key, but invalid cert bytes
		_, keyPEM := genSelfSignedCert("localhost", time.Now().Add(-1*time.Hour), time.Now().Add(1*time.Hour))
		certPath, keyPath := write([]byte("not-a-cert"), keyPEM)
		_, err := loadAndValidateTLSCertificate(certPath, keyPath)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("failed to parse certificate PEM"))
	})
})

var _ = Describe("hot certificate reload (watchCertFilesWithStop)", func() {
	var (
		tmpDir   string
		certPath string
		keyPath  string
		reloadCh chan struct{}
		stopCh   chan struct{}
	)

	BeforeEach(func() {
		var err error
		tmpDir, err = os.MkdirTemp("", "watcher-ut-*")
		Expect(err).ToNot(HaveOccurred())
		certPath = filepath.Join(tmpDir, "tls.crt")
		keyPath = filepath.Join(tmpDir, "tls.key")

		// initial valid cert
		certPEM, keyPEM := genSelfSignedCert("localhost", time.Now().Add(-1*time.Hour), time.Now().Add(1*time.Hour))
		Expect(os.WriteFile(certPath, certPEM, 0o600)).To(Succeed())
		Expect(os.WriteFile(keyPath, keyPEM, 0o600)).To(Succeed())

		reloadCh = make(chan struct{}, 10)
		stopCh = make(chan struct{})
	})

	AfterEach(func() {
		close(stopCh)
		_ = os.RemoveAll(tmpDir)
	})

	runWatcher := func() {
		go watchCertFilesWithStop(certPath, keyPath, func() { reloadCh <- struct{}{} }, stopCh)
		time.Sleep(150 * time.Millisecond) // allow watcher to start
	}

	It("triggers reload when certificate file is written", func() {
		runWatcher()
		Expect(os.WriteFile(certPath, []byte("updated-cert"), 0o600)).To(Succeed())
		Eventually(func() int { return len(reloadCh) }, 3*time.Second, 100*time.Millisecond).Should(BeNumerically(">=", 1))
	})

	It("triggers reload when key file is written", func() {
		runWatcher()
		Expect(os.WriteFile(keyPath, []byte("updated-key"), 0o600)).To(Succeed())
		Eventually(func() int { return len(reloadCh) }, 3*time.Second, 100*time.Millisecond).Should(BeNumerically(">=", 1))
	})

	It("does not trigger reload for unrelated file changes", func() {
		runWatcher()
		other := filepath.Join(tmpDir, "other.txt")
		Expect(os.WriteFile(other, []byte("something"), 0o600)).To(Succeed())
		Consistently(func() int { return len(reloadCh) }, 500*time.Millisecond, 50*time.Millisecond).Should(Equal(0))
	})
})

// genSelfSignedCert creates a minimal self-signed cert with the given validity window.
func genSelfSignedCert(cn string, notBefore, notAfter time.Time) ([]byte, []byte) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).ToNot(HaveOccurred())

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	Expect(err).ToNot(HaveOccurred())

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	Expect(err).ToNot(HaveOccurred())

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return certPEM, keyPEM
}

// test-only watcher: watches the two files directly and can be stopped via stopCh.
func watchCertFilesWithStop(certPath, keyPath string, onChange func(), stopCh <-chan struct{}) {
	absCertPath, _ := filepath.Abs(certPath)
	absKeyPath, _ := filepath.Abs(keyPath)

	watcher, err := fsnotify.NewWatcher()
	Expect(err).ToNot(HaveOccurred())

	add := func(p string) {
		Expect(watcher.Add(p)).To(Succeed())
	}

	add(absCertPath)
	add(absKeyPath)

	triggerOps := fsnotify.Write | fsnotify.Create | fsnotify.Remove | fsnotify.Rename

	go func() {
		defer watcher.Close()
		for {
			select {
			case <-stopCh:
				return
			case evt, ok := <-watcher.Events:
				if !ok {
					return
				}
				if evt.Op&triggerOps != 0 && (samePath(evt.Name, absCertPath) || samePath(evt.Name, absKeyPath)) {
					onChange()
				}
			case <-watcher.Errors:
				// ignore in tests
			}
		}
	}()
}

func samePath(a, b string) bool {
	aa := filepath.Clean(a)
	bb := filepath.Clean(b)
	return aa == bb
}
