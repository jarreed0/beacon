package main

import (
//	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
        "flag"
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net"
	"os"
//	"strings"
	"time"
)

type Message struct {
	Msg       string `json:"message"`
	Sender    string `json:"sender"`
	Timestamp int64  `json:"timestamp"`
}

type Config struct {
	Sender  string   `yaml:"sender"`
	Targets []string `yaml:"targets"`
}

func main() {
        // message := "Hello, World!"
        // Parse command-line flags
        msgPtr := flag.String("msg", "", "The message to encrypt")
        flag.Parse()

        // Check if message is provided
        if *msgPtr == "" {
                fmt.Println("Please provide a message using the '-msg' flag")
                os.Exit(1)
        }

        message := *msgPtr

	// Load configuration
	config, err := loadConfig("beacon.conf")
	if err != nil {
		fmt.Println("Failed to load config:", err)
		os.Exit(1)
	}

	// Generate message
	jsonData, err := generateJSON(message, config.Sender)
	if err != nil {
		fmt.Println("Failed to generate JSON:", err)
		os.Exit(1)
	}

	fmt.Println("Generated JSON:", string(jsonData))

	// Send message to each target
	for _, target := range config.Targets {
		err := sendMessage(target, jsonData)
		if err != nil {
			fmt.Println("Failed to send message to", target, ":", err)
		} else {
			fmt.Println("Message sent to", target)
		}
	}
}

func loadConfig(filename string) (*Config, error) {
	config := &Config{}

	configData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration file: %w", err)
	}

	err = yaml.Unmarshal(configData, config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal configuration: %w", err)
	}

	return config, nil
}

func generateJSON(message, sender string) ([]byte, error) {
	timestamp := time.Now().Unix()

	msg := Message{
		Msg:       message,
		Sender:    sender,
		Timestamp: timestamp,
	}

	jsonData, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	return jsonData, nil
}

func sendMessage(contact string, data []byte) error {
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:42398", contact))
	if err != nil {
		return err
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return fmt.Errorf("failed to establish UDP connection: %w", err)
	}
	defer conn.Close()

	// Encrypt the data
	encryptedData, err := encrypt(data)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	_, err = conn.Write(encryptedData)
	if err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	return nil
}

func encrypt(data []byte) ([]byte, error) {
	// Load public key
	publicKeyBytes, err := ioutil.ReadFile("public_key.pem")
	if err != nil {
		return nil, fmt.Errorf("failed to read public key: %w", err)
	}

	block, _ := pem.Decode(publicKeyBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPublicKey := publicKey.(*rsa.PublicKey)

	// Encrypt the data
	encryptedData, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, data)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	return encryptedData, nil
}

func decrypt(encryptedData []byte) ([]byte, error) {
	// Load private key
	privateKeyBytes, err := ioutil.ReadFile("private_key.pem")
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	block, _ := pem.Decode(privateKeyBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode private key")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	rsaPrivateKey := privateKey.(*rsa.PrivateKey)

	// Decrypt the data
	decryptedData, err := rsa.DecryptPKCS1v15(rand.Reader, rsaPrivateKey, encryptedData)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return decryptedData, nil
}

func printJSON(data []byte) error {
	var msg Message

	err := json.Unmarshal(data, &msg)
	if err != nil {
		return err
	}

	fmt.Println("Message:", msg.Msg)
	fmt.Println("Sender:", msg.Sender)
	fmt.Println("Timestamp:", msg.Timestamp)

	return nil
}
