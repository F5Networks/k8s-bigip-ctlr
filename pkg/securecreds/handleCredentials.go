package securecreds

import (
	"encoding/json"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"net"
	"os"
)

const socketPath = "/tmp/secure_cis.sock"

// formatCredentials creates a map of credentials for BIGIP and GTM
// It returns a map[string]string containing the formatted credentials
func formatCredentials(bigipUser, bigipPass, gtmUser, gtmPass string) map[string]string {
	credentials := make(map[string]string)

	// Get LTM credentials
	credentials["bigip_username"] = bigipUser
	credentials["bigip_password"] = bigipPass

	// Get GTM credentials
	credentials["gtm_username"] = gtmUser
	credentials["gtm_password"] = gtmPass

	return credentials
}

// shouldEncryptCredentials checks if credentials need to be encrypted
// It returns true if:
// - GTM credentials are not set (gtmUser and gtmPass are empty)
// - BIGIP credentials are not set via environment variables
// - GTM credentials are not set via environment variables
// Otherwise, it returns false
func shouldEncryptCredentials(gtmUser, gtmPass string) bool {
	var isGTMSet bool
	if gtmUser != "" && gtmPass != "" {
		isGTMSet = true
	}
	if os.Getenv("BIGIP_USERNAME") != "" && os.Getenv("BIGIP_PASSWORD") != "" && isGTMSet != true {
		return false
	}

	if os.Getenv("GTM_BIGIP_USERNAME") != "" && os.Getenv("GTM_BIGIP_PASSWORD") != "" {
		return false
	}

	return true
}

// Add this function with its fucntionality in a function header format
// HandleCredentialsRequest handles the secure credentials request for CIS
// sets up a Unix socket and sends the data to the client.
// This function is responsible for securely handling
// and transmitting BIGIP and GTM credentials.
func HandleCredentialsRequest(bigipUser, bigipPass, gtmUser, gtmPass string) {
	if !shouldEncryptCredentials(gtmUser, gtmPass) {
		return
	}

	// Create the Unix socket
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("[ERROR] Failed to create Unix socket: %v", err)
	}
	defer os.Remove(socketPath) // Cleanup after server stops

	// Generate encryption key and credentials
	credentials := formatCredentials(bigipUser, bigipPass, gtmUser, gtmPass)
	messageJSON, _ := json.Marshal(credentials)
	log.Debugf("[INFO] Server is listening on %s\n", socketPath)

	conn, err := listener.Accept()
	if err != nil {
		log.Fatalf("[ERROR] Failed to accept connection: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte(messageJSON))
	if err != nil {
		log.Fatalf("[ERROR] Failed to send data to client: %v", err)
	}

	log.Debug("[INFO] Data sent to client. Closing connection.")
}
