package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net"
	"sync"
)

// EncryptionManager handles all encryption/decryption for a connection
type EncryptionManager struct {
	privateKey *ecdh.PrivateKey
	sharedKey  []byte
	gcm        cipher.AEAD
	isKeySet   bool
	mutex      sync.RWMutex
}

// NewEncryptionManager creates a new encryption manager with ECDH key pair
func NewEncryptionManager() (*EncryptionManager, error) {
	curve := ecdh.P256()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	return &EncryptionManager{
		privateKey: privateKey,
		isKeySet:   false,
	}, nil
}

// GetPublicKey returns the public key bytes for key exchange
func (em *EncryptionManager) GetPublicKey() []byte {
	return em.privateKey.PublicKey().Bytes()
}

// SetSharedSecret establishes the shared secret from peer's public key
func (em *EncryptionManager) SetSharedSecret(peerPublicKeyBytes []byte) error {
	em.mutex.Lock()
	defer em.mutex.Unlock()

	curve := ecdh.P256()
	peerPublicKey, err := curve.NewPublicKey(peerPublicKeyBytes)
	if err != nil {
		return fmt.Errorf("invalid peer public key: %w", err)
	}

	sharedSecret, err := em.privateKey.ECDH(peerPublicKey)
	if err != nil {
		return fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Derive AES key from shared secret using SHA256
	hash := sha256.Sum256(sharedSecret)
	em.sharedKey = hash[:]

	// Create AES-GCM cipher
	block, err := aes.NewCipher(em.sharedKey)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	em.gcm, err = cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	em.isKeySet = true
	return nil
}

// IsReady returns true if encryption is ready to use
func (em *EncryptionManager) IsReady() bool {
	em.mutex.RLock()
	defer em.mutex.RUnlock()
	return em.isKeySet
}

// Encrypt encrypts data using AES-GCM, returns [nonce][ciphertext+tag]
func (em *EncryptionManager) Encrypt(plaintext []byte) ([]byte, error) {
	em.mutex.RLock()
	defer em.mutex.RUnlock()

	if !em.isKeySet {
		return nil, fmt.Errorf("encryption not ready: shared secret not established")
	}

	// Generate random nonce
	nonce := make([]byte, em.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate
	ciphertext := em.gcm.Seal(nil, nonce, plaintext, nil)

	// Return [nonce][ciphertext+tag]
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result, nonce)
	copy(result[len(nonce):], ciphertext)

	return result, nil
}

// Decrypt decrypts data, expects [nonce][ciphertext+tag] format
func (em *EncryptionManager) Decrypt(data []byte) ([]byte, error) {
	em.mutex.RLock()
	defer em.mutex.RUnlock()

	if !em.isKeySet {
		return nil, fmt.Errorf("decryption not ready: shared secret not established")
	}

	nonceSize := em.gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("data too short for nonce")
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	plaintext, err := em.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// SecureConn wraps a UDP connection with encryption
type SecureConn struct {
	conn      UDPConn // Interface for UDP operations
	encMgr    *EncryptionManager
	isEnabled bool
}

// UDPConn interface to allow mocking and abstraction
type UDPConn interface {
	WriteToUDP([]byte, *net.UDPAddr) (int, error)
	ReadFromUDP([]byte) (int, *net.UDPAddr, error)
}

// NewSecureConn creates a new secure connection wrapper
func NewSecureConn(conn UDPConn) (*SecureConn, error) {
	encMgr, err := NewEncryptionManager()
	if err != nil {
		return nil, err
	}

	return &SecureConn{
		conn:      conn,
		encMgr:    encMgr,
		isEnabled: false,
	}, nil
}

// EnableEncryption turns on encryption after key exchange
func (sc *SecureConn) EnableEncryption() {
	sc.isEnabled = true
}

// IsEncryptionReady returns true if encryption is available
func (sc *SecureConn) IsEncryptionReady() bool {
	return sc.encMgr.IsReady()
}

// GetPublicKey returns public key for handshake
func (sc *SecureConn) GetPublicKey() []byte {
	return sc.encMgr.GetPublicKey()
}

// SetPeerPublicKey establishes shared secret
func (sc *SecureConn) SetPeerPublicKey(peerKey []byte) error {
	return sc.encMgr.SetSharedSecret(peerKey)
}

// SecureWriteToUDP encrypts and sends data
func (sc *SecureConn) SecureWriteToUDP(data []byte, addr *net.UDPAddr) (int, error) {
	// Don't encrypt handshake packets or if encryption is disabled
	if !sc.isEnabled || !sc.encMgr.IsReady() {
		return sc.conn.WriteToUDP(data, addr)
	}

	encrypted, err := sc.encMgr.Encrypt(data)
	if err != nil {
		return 0, fmt.Errorf("encryption failed: %w", err)
	}

	return sc.conn.WriteToUDP(encrypted, addr)
}

// SecureReadFromUDP reads and decrypts data
func (sc *SecureConn) SecureReadFromUDP(buffer []byte) (int, *net.UDPAddr, []byte, error) {
	n, addr, err := sc.conn.ReadFromUDP(buffer)
	if err != nil {
		return n, addr, nil, err
	}

	data := buffer[:n]

	// Don't decrypt handshake packets or if encryption is disabled
	if !sc.isEnabled || !sc.encMgr.IsReady() {
		return n, addr, data, nil
	}

	decrypted, err := sc.encMgr.Decrypt(data)
	if err != nil {
		// If decryption fails, it might be an unencrypted packet
		// Return original data but log the error
		fmt.Printf("Decryption failed for packet from %s: %v\n", addr, err)
		return n, addr, data, nil
	}

	return len(decrypted), addr, decrypted, nil
}
