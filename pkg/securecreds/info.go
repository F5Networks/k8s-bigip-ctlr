package securecreds

// Encryption Details:
//
// 1. Key Generation:
//    - A 32-byte (256-bit) random key is generated using crypto/rand
//    - This key is used for AES encryption
//
// 2. Encryption Algorithm:
//    - AES (Advanced Encryption Standard) in GCM (Galois/Counter Mode) is used
//    - AES-GCM provides both confidentiality and authenticity (encryption and MAC)
//
// 3. Process:
//    a. Create AES cipher using the generated key
//    b. Create GCM (AEAD) from the cipher
//    c. Generate a random nonce (12 bytes for GCM)
//    d. Encrypt the credentials (JSON-encoded) using GCM.Seal()
//       - This produces the ciphertext and appends the authentication tag
//    e. Prepend the nonce to the ciphertext
//
// 4. Output:
//    - The final encrypted data consists of: nonce + ciphertext + auth tag
//    - This is then base64 encoded for transmission
//
// 5. Security Features:
//    - Authenticated Encryption: Protects against tampering and forgery
//    - Unique key per session: Enhances forward secrecy
//    - Random nonce: Ensures unique ciphertexts even for identical plaintexts
//
// ┌─────────────────┐
// │HandleCredentials│
// │    Request      │
// └────────┬────────┘
//          │
//          ▼
// ┌─────────────────┐     Yes     ┌─────────────────┐
// │ Env Vars Present│──────────────▶│ Return (Skip    │
// │                 │              │ Socket Creation)│
// └────────┬────────┘              └─────────────────┘
//          │ No
//          ▼
// ┌─────────────────┐
// │ openUnixSocket  │
// └────────┬────────┘
//          │
//          ▼
// ┌─────────────────┐
// │handleConnection │
// └────────┬────────┘
//          │
//          ▼
// ┌─────────────────┐
// │generateDynamic  │
// │      Key        │
// └────────┬────────┘
//          │
//          ▼
// ┌─────────────────┐
// │  getCredentials │
// └────────┬────────┘
//          │
//          ▼
// ┌─────────────────┐
// │encryptCredentials│
// └────────┬────────┘
//          │
//          ▼
// ┌─────────────────┐
// │ Send Encrypted  │
// │ Data over Socket│
// └─────────────────┘

// Block Diagram for Python Driver Decryption Process:
//
// ┌─────────────────┐
// │  Python Driver  │
// │    Request      │
// └────────┬────────┘
//          │
//          ▼
// ┌─────────────────┐     No     ┌─────────────────┐
// │ Check Env Vars  │───────────▶│  Unix Socket    │
// │ for Credentials │            │   Connection    │
// └────────┬────────┘            └────────┬────────┘
//          │                              │
//          │ Yes                          │
//          │                              ▼
//          │                     ┌─────────────────┐
//          │                     │  Receive JSON   │
//          │                     │    Response     │
//          │                     └────────┬────────┘
//          │                              │
//          │                              ▼
//          │                     ┌─────────────────┐
//          │                     │ Parse JSON and  │
//          │                     │Extract Key/Data │
//          │                     └────────┬────────┘
//          │                              │
//          │                              ▼
//          │                     ┌─────────────────┐
//          │                     │   AES-GCM       │
//          │                     │   Decryption    │
//          │                     └────────┬────────┘
//          │                              │
//          ▼                              ▼
// ┌─────────────────┐            ┌─────────────────┐
// │  Credentials    │            │  Credentials    │
// │    Obtained     │◀───────────│    Obtained     │
// └─────────────────┘            └─────────────────┘
//
// Process Flow:
// 1. Python Driver initiates a request
// 2. Check if credentials are in environment variables
// 3. If not, establish Unix socket connection
// 4. Receive JSON response with key and encrypted data
// 5. Parse JSON to extract key and encrypted data
// 6. Use AES-GCM to decrypt the data
// 7. Obtain the decrypted credentials (username and password)

// Security Considerations:
// - Environment variables provide a secure way to store credentials
// - Unix socket ensures secure local communication
// - AES-GCM provides both confidentiality and authenticity
// - Unique key per session enhances security
