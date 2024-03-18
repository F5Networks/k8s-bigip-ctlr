package ipam

import (
	"context"
	"encoding/json"
	ipamsvc "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/ipam/pb"
	log "github.com/F5Networks/k8s-bigip-ctlr/v3/pkg/vlogger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	grpcMetadata "google.golang.org/grpc/metadata"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"os"
	"strings"
	"time"
)

const (
	NotEnabled = iota
	InvalidInput
	NotRequested
	Requested
	Allocated
	ClientToken = "x-client-id"
	ServerToken = "x-server-id"
)

type IPAMHandler struct {
	ServiceToken string
	URI          string
	Insecure     bool
	ticker       *time.Ticker
	done         chan bool
	ipamGrpcCli  *grpc.ClientConn
	kubeClient   kubernetes.Interface
	tokenPath    string
	audiences    []string
}

func NewIpamHandler(uri string, kubeClient kubernetes.Interface) *IPAMHandler {
	tokenPath := os.Getenv("TOKEN_PATH")
	if tokenPath == "" {
		log.Fatalf("TOKEN_PATH environment variable not set for IPAM")
	}
	audiences := os.Getenv("FIC_AUDIENCES")
	if audiences == "" {
		log.Fatalf("AUDIENCES environment variable not set for IPAM")
	}
	return &IPAMHandler{
		ticker:      time.NewTicker(300 * time.Second),
		done:        make(chan bool),
		ipamGrpcCli: NewGRPCClient(uri),
		kubeClient:  kubeClient,
		URI:         uri,
		tokenPath:   tokenPath,
		audiences:   strings.Split(audiences, ","),
	}
}

func (h *IPAMHandler) Stop() {
	h.ticker.Stop()
	h.done <- true
}

func (h *IPAMHandler) Start() {
	h.setServiceToken()
	go func() {
		for {
			select {
			case <-h.done:
				return
			case <-h.ticker.C:
				// Set service account token
				h.setServiceToken()
			}
		}
	}()
}

func (h *IPAMHandler) setServiceToken() {
	b, err := os.ReadFile(h.tokenPath)
	if err != nil {
		panic(err)
	}
	h.ServiceToken = string(b)
}

// NewGRPCClient creates a new gRPC connection.
// host should be of the form domain:port, e.g., example.com:443
func NewGRPCClient(host string) *grpc.ClientConn {
	var opts []grpc.DialOption
	if host != "" {
		opts = append(opts, grpc.WithAuthority(host))
	}

	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))

	conn, err := grpc.Dial(host, opts...)
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	return conn
}

func (h *IPAMHandler) ReleaseGrpcIP(ipamLabel, key string) string {
	grpcReq := ipamsvc.NewIpamGRPCServiceClient(h.ipamGrpcCli)
	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	// Add service token to gRPC Request.
	ctx = grpcMetadata.AppendToOutgoingContext(ctx, ClientToken, h.ServiceToken)

	defer cancel()
	if key != "" {
		// Make RPC using the context with the metadata.
		var header grpcMetadata.MD
		out, err := grpcReq.ReleaseIP(ctx, &ipamsvc.ReleaseIPRequest{Label: ipamLabel, Hostname: key}, grpc.Header(&header))
		if err != nil {
			log.Errorf("[IPAM] Error deallocating IP: %v", err)
			return ""
		}
		if auth, ok := header[ServerToken]; ok && h.valid(auth) {
			return out.Ipaddress
		} else {
			log.Debugf("[IPAM] Invalid headers or Unauthorized to perform the action with headers: %v", header)
			return ""
		}
	} else {
		log.Debugf("[IPAM] Invalid host and key.")
		return ""
	}
}

func (h *IPAMHandler) AllocateGrpcIP(ipamLabel, key string) (string, int) {
	grpcReq := ipamsvc.NewIpamGRPCServiceClient(h.ipamGrpcCli)
	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	// Add service token to gRPC Request.
	ctx = grpcMetadata.AppendToOutgoingContext(ctx, ClientToken, h.ServiceToken)

	defer cancel()
	var header grpcMetadata.MD
	ip, err := grpcReq.AllocateIP(ctx, &ipamsvc.AllocateIPRequest{Label: ipamLabel, Hostname: key}, grpc.Header(&header))

	if err != nil {
		log.Errorf("[IPAM] Error allocating IP: %v", err)
		return "", InvalidInput
	}
	if auth, ok := header[ServerToken]; ok && h.valid(auth) {
		return ip.Ipaddress, Allocated
	} else {
		log.Debugf("[IPAM] Invalid headers or Unauthorized to perform the action with headers: %v", header)
		return "", InvalidInput
	}
}

// valid validates the authorization.
func (h *IPAMHandler) valid(authorization []string) bool {
	if len(authorization) < 1 {
		return false
	}
	// Perform the token validation here. For the sake of this example, the code
	// here forgoes any of the usual OAuth2 token validation and instead checks
	// for a token matching an arbitrary string.
	ctx := context.TODO()
	tr := authv1.TokenReview{
		Spec: authv1.TokenReviewSpec{
			Token:     authorization[0],
			Audiences: h.audiences,
		},
	}
	result, err := h.kubeClient.AuthenticationV1().TokenReviews().Create(ctx, &tr, metav1.CreateOptions{})
	if err != nil {
		log.Errorf("error validating token: %v", err)
		return false
	}
	log.Debugf("%s\n", prettyPrint(result.Status))
	if result.Status.Authenticated {
		return true
	}
	return false
}

func prettyPrint(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "\t")
	return string(s)
}
