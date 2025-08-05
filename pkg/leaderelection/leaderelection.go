// Package leaderelection implements a simple leader election mechanism using a BIG-IP internal data group.
package leaderelection

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/bigiphandler"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/httpclient"
	"github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/tokenmanager"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"github.com/f5devcentral/go-bigip"
)

const (
	leaderRecordName = "leader"
)

// LeaderElectorConfig holds the configuration for LeaderElector
type LeaderElectorConfig struct {
	CandidateID       string
	DataGroupName     string
	HeartbeatTimeout  time.Duration
	HeartbeatInterval time.Duration
	BigipHost         string
	Username          string
	Password          string
	TrustedCerts      string
	SslInsecure       bool
	UserAgent         string
	Teem              bool
}

// LeaderElector implements leader election using BIG-IP datagroups with secure token-based authentication
type LeaderElector struct {
	config       LeaderElectorConfig
	tokenManager tokenmanager.TokenManagerInterface
	bigipHandler *bigiphandler.BigIPHandler
	stopCh       chan struct{}
	mu           sync.Mutex
	isLeader     bool
	httpClient   *http.Client
	stopped      bool
}

// NewLeaderElector creates a new LeaderElector instance with shared tokenmanager and bigiphandler integration
func NewLeaderElector(config LeaderElectorConfig) (*LeaderElector, error) {
	// Create HTTP client configuration
	clientConfig := httpclient.ClientConfig{
		TrustedCerts: config.TrustedCerts,
		SSLInsecure:  config.SslInsecure,
		Timeout:      30 * time.Second,
	}

	// Get HTTP client from factory
	factory := httpclient.GetFactory()
	clientKey := fmt.Sprintf("leaderelection-%s", config.BigipHost)
	httpClient := factory.GetOrCreateClient(clientKey, clientConfig)

	// Use shared token manager instead of creating a new instance
	sharedTM := tokenmanager.GetSharedTokenManager()
	tm := sharedTM.GetOrCreateTokenManager(
		config.BigipHost,
		config.Username,
		config.Password,
		httpClient,
	)

	// Create BIG-IP session using shared tokenmanager
	bigipSession := bigiphandler.CreateSession(
		config.BigipHost,
		tm.GetToken(),
		config.UserAgent,
		config.TrustedCerts,
		config.SslInsecure,
		config.Teem,
	)

	// Create bigiphandler
	handler := &bigiphandler.BigIPHandler{
		Bigip: bigipSession,
	}

	return &LeaderElector{
		config:       config,
		tokenManager: tm,
		bigipHandler: handler,
		stopCh:       make(chan struct{}),
		httpClient:   httpClient,
	}, nil
}

// Start begins the leader election process
func (le *LeaderElector) Start() {
	// Token manager lifecycle is handled automatically by the shared token manager
	// No need to manually start token refresh - it's handled when GetToken() is called

	// Start leader election processes
	go le.monitorLeader()
	go le.heartbeatLoop()

	log.Infof("[Leader Election] Started leader election for candidate %s", le.config.CandidateID)
}

// Stop stops the leader election process
func (le *LeaderElector) Stop() {
	le.mu.Lock()
	defer le.mu.Unlock()

	if le.stopped {
		return
	}
	close(le.stopCh)
	le.stopped = true
	log.Infof("[Leader Election] Stopped leader election for candidate %s", le.config.CandidateID)
}

// IsLeader returns whether this instance is currently the leader
func (le *LeaderElector) IsLeader() bool {
	le.mu.Lock()
	defer le.mu.Unlock()
	return le.isLeader
}

// GetCandidateID returns the candidate ID for this leader elector instance
func (le *LeaderElector) GetCandidateID() string {
	return le.config.CandidateID
}

// heartbeatLoop sends periodic heartbeats when this instance is the leader
func (le *LeaderElector) heartbeatLoop() {
	ticker := time.NewTicker(le.config.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-le.stopCh:
			return
		case <-ticker.C:
			le.mu.Lock()
			if le.isLeader {
				if err := le.writeHeartbeat(); err != nil {
					log.Errorf("[Leader Election] Failed to write heartbeat: %v", err)
					// If we can't write heartbeat, step down as leader
					le.isLeader = false
				}
			}
			le.mu.Unlock()
		}
	}
}

// monitorLeader monitors the current leader and attempts to become leader if needed
func (le *LeaderElector) monitorLeader() {
	for {
		select {
		case <-le.stopCh:
			return
		default:
		}

		currentLeader, modTime, err := le.readLeader()
		if err != nil {
			log.Debugf("[Leader Election] Error reading leader data: %v", err)
			time.Sleep(le.config.HeartbeatInterval)
			continue
		}

		now := time.Now()
		le.mu.Lock()

		// Check if current leader's heartbeat has expired
		if modTime.IsZero() || now.Sub(modTime) > le.config.HeartbeatTimeout {
			if !le.isLeader {
				log.Infof("[Leader Election] No active leader found. Candidate %s becoming leader", le.config.CandidateID)
				le.isLeader = true
				if err := le.writeHeartbeat(); err != nil {
					log.Errorf("[Leader Election] Failed to write initial heartbeat: %v", err)
					le.isLeader = false
				}
			}
		} else {
			// There's an active leader
			if currentLeader != le.config.CandidateID {
				if le.isLeader {
					log.Infof("[Leader Election] Candidate %s stepping down. Current leader is %s", le.config.CandidateID, currentLeader)
					le.isLeader = false
				}
			}
		}

		le.mu.Unlock()
		time.Sleep(le.config.HeartbeatInterval)
	}
}

// writeHeartbeat writes the current candidate's heartbeat to the datagroup
func (le *LeaderElector) writeHeartbeat() error {
	content := fmt.Sprintf("%s %d", le.config.CandidateID, time.Now().Unix())

	// Update BIG-IP session token before making API calls
	le.updateBigIPToken()

	return le.updateDataGroupValue(content)
}

// readLeader reads the current leader information from the datagroup
func (le *LeaderElector) readLeader() (string, time.Time, error) {
	// Update BIG-IP session token before making API calls
	le.updateBigIPToken()

	data, err := le.getDataGroupValue(le.config.DataGroupName)
	if err != nil {
		return "", time.Time{}, err
	}

	var leader string
	var timestamp int64
	_, err = fmt.Sscanf(data, "%s %d", &leader, &timestamp)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to parse leader data: %v", err)
	}

	return leader, time.Unix(timestamp, 0), nil
}

// updateBigIPToken updates the BIG-IP session token from tokenmanager
func (le *LeaderElector) updateBigIPToken() {
	if bigipClient, ok := le.bigipHandler.Bigip.(*bigip.BigIP); ok {
		bigipClient.Token = le.tokenManager.GetToken()
	}
}

// getDataGroupValue retrieves a value from the leader election datagroup
func (le *LeaderElector) getDataGroupValue(name string) (string, error) {
	bigipClient, ok := le.bigipHandler.Bigip.(*bigip.BigIP)
	if !ok {
		return "", fmt.Errorf("invalid bigip client type")
	}

	datagroup, err := bigipClient.GetInternalDataGroup(name)
	if err != nil {
		return "", fmt.Errorf("failed to get datagroup %s: %v", name, err)
	}

	if datagroup == nil {
		return "", fmt.Errorf("datagroup %s not found", name)
	}

	if len(datagroup.Records) == 0 {
		return "", fmt.Errorf("datagroup %s is empty", name)
	}

	// Find the leader record
	for _, record := range datagroup.Records {
		if record.Name == leaderRecordName {
			return record.Data, nil
		}
	}

	return "", fmt.Errorf("leader record not found in datagroup %s", name)
}

// updateDataGroupValue updates the leader election datagroup with new content
func (le *LeaderElector) updateDataGroupValue(content string) error {
	bigipClient, ok := le.bigipHandler.Bigip.(*bigip.BigIP)
	if !ok {
		return fmt.Errorf("invalid bigip client type")
	}

	// Create the datagroup structure
	datagroup := &bigip.DataGroup{
		Name: le.config.DataGroupName,
		Type: "string",
		Records: []bigip.DataGroupRecord{
			{
				Name: leaderRecordName,
				Data: content,
			},
		},
	}

	// Check if datagroup exists
	existing, err := bigipClient.GetInternalDataGroup(le.config.DataGroupName)
	if err != nil || existing == nil {
		// Create new datagroup - using AddInternalDataGroup instead of CreateInternalDataGroup
		if err := bigipClient.AddInternalDataGroup(datagroup); err != nil {
			return fmt.Errorf("failed to create datagroup %s: %v", le.config.DataGroupName, err)
		}
		log.Debugf("[Leader Election] Created datagroup %s", le.config.DataGroupName)
	} else {
		// Update existing datagroup
		/*if err := bigipClient.ModifyInternalDataGroup(dataGroupName, datagroup); err != nil {
			return fmt.Errorf("failed to update datagroup %s: %v", dataGroupName, err)
		}*/
		log.Debugf("[Leader Election] Updated datagroup %s", le.config.DataGroupName)
	}

	log.Debugf("[Leader Election] Leader %s wrote heartbeat", le.config.CandidateID)
	return nil
}
