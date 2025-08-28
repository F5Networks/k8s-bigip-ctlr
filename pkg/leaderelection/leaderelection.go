// Package leaderelection implements a simple leader election mechanism using a BIG-IP internal data group.
package leaderelection

import (
	"fmt"
	"net/http"
	"strings"
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
	config             LeaderElectorConfig
	tokenManager       tokenmanager.TokenManagerInterface
	bigipHandler       *bigiphandler.BigIPHandler
	stopCh             chan struct{}
	mu                 sync.Mutex
	isLeader           bool
	httpClient         *http.Client
	stopped            bool
	leadershipCallback func(isLeader bool)
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

// SetLeadershipCallback sets the callback function to be called when becoming leader
func (le *LeaderElector) SetLeadershipCallback(callback func(isLeader bool)) {
	le.mu.Lock()
	defer le.mu.Unlock()
	le.leadershipCallback = callback
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

		previousLeaderStatus := le.isLeader

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

		// Trigger callback only when becoming leader (not when stepping down)
		if !previousLeaderStatus && le.isLeader && le.leadershipCallback != nil {
			// Call callback without holding the lock to avoid deadlocks
			callback := le.leadershipCallback
			le.mu.Unlock()
			callback(true)
			le.mu.Lock()
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
		// Check if this is a "no data group" or "empty data group" scenario
		errorStr := strings.ToLower(err.Error())
		if strings.Contains(errorStr, "404") ||
			strings.Contains(errorStr, "not found") ||
			strings.Contains(errorStr, "is empty") {
			// Return zero time to indicate no current leader - this will trigger election
			return "", time.Time{}, nil
		}
		// For other errors (network, auth, etc.), return the error
		return "", time.Time{}, err
	}

	var leader string
	var timestamp int64
	_, err = fmt.Sscanf(data, "%s %d", &leader, &timestamp)
	if err != nil {
		// If we can't parse the data, treat it as no current leader
		log.Warningf("Warning: Could not parse leader data '%s': %v", data, err)
		return "", time.Time{}, nil
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
	var datagroup interface{}
	var err error

	datagroup, err = le.bigipHandler.GetInternalDataGroup(name)

	// If API call returned an error, return it
	if err != nil {
		return "", fmt.Errorf("failed to get datagroup %s: %v", name, err)
	}

	if datagroup == nil {
		return "", fmt.Errorf("datagroup %s not found", name)
	}

	// Type assert to get the actual datagroup structure
	dg, ok := datagroup.(*bigip.DataGroup)
	if !ok {
		return "", fmt.Errorf("unexpected datagroup type for %s", name)
	}

	if len(dg.Records) == 0 {
		return "", fmt.Errorf("datagroup %s is empty", name)
	}

	// Find the leader record
	for _, record := range dg.Records {
		if record.Name == leaderRecordName {
			return record.Data, nil
		}
	}

	return "", fmt.Errorf("leader record not found in datagroup %s", name)
}

// updateDataGroupValue updates the leader election datagroup with new content
func (le *LeaderElector) updateDataGroupValue(content string) error {
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

	var existing interface{}
	var getErr error
	existing, getErr = le.bigipHandler.GetInternalDataGroup(le.config.DataGroupName)
	// Check if datagroup exists
	if getErr != nil || existing == nil {
		log.Debugf("[Leader Election] Creating datagroup %s", le.config.DataGroupName)
		return le.bigipHandler.CreateInternalDataGroup(datagroup)
	} else {
		log.Debugf("[Leader Election] Updating datagroup %s", le.config.DataGroupName)
		return le.bigipHandler.ModifyInternalDataGroupRecords(datagroup)
	}
}
