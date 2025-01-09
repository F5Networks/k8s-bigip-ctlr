package securecreds

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	log "github.com/F5Networks/k8s-bigip-ctlr/v2/pkg/vlogger"
	"io"
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
// It checks if credentials need to be encrypted, sets up a Unix socket,
// generates an encryption key and encrypted payload, and sends the data
// to the client. This function is responsible for securely handling
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
	key, _ := generateDynamicKey()
	credentials := formatCredentials(bigipUser, bigipPass, gtmUser, gtmPass)
	encryptedPayload, _ := encryptCredentials(credentials, key)

	// Send key and encrypted payload
	message := map[string]string{
		"key":            key,
		"encrypted_data": encryptedPayload,
	}
	messageJSON, _ := json.Marshal(message)

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

func generateDynamicKey() (string, error) {
	key := make([]byte, 32) // 256-bit key
	_, err := rand.Read(key)
	if err != nil {
		return "", fmt.Errorf("failed to generate AES key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

func encryptCredentials(credentials map[string]string, key string) (string, error) {
	// Decode the Base64 key
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("failed to decode AES key: %v", err)
	}

	// Convert credentials map to JSON
	credentialsJSON, err := json.Marshal(credentials)
	if err != nil {
		return "", fmt.Errorf("failed to marshal credentials: %v", err)
	}

	// Create AES cipher block
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %v", err)
	}

	// Use AES-GCM for encryption
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM cipher: %v", err)
	}

	// Generate a nonce (12 bytes for AES-GCM)
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Encrypt the credentials JSON
	ciphertext := aesGCM.Seal(nil, nonce, credentialsJSON, nil)

	// Combine nonce + ciphertext + tag
	encryptedPayload := append(nonce, ciphertext...)

	// Encode to Base64
	return base64.StdEncoding.EncodeToString(encryptedPayload), nil
}
