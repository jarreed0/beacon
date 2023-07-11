package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"sync"
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

var (
	mu     sync.Mutex
	targets []string
)

func main() {
	// Load configuration
	config, err := loadConfig("beacon.conf")
	if err != nil {
		fmt.Println("Failed to load config:", err)
		os.Exit(1)
	}

	targets = config.Targets

	// Start the server
	err = startServer()
	if err != nil {
		fmt.Println("Server error:", err)
		os.Exit(1)
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

func startServer() error {
	udpAddr, err := net.ResolveUDPAddr("udp", ":42398")
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}
	defer conn.Close()

	fmt.Println("Server started, listening on port 42398")

	buf := make([]byte, 1024)

	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Read error:", err)
			continue
		}

		data := buf[:n]

                fmt.Printf("Received message from %s\n", addr.IP)

		// Decrypt the data
		decryptedData, err := decrypt(data)
		if err != nil {
			// Forward to other targets
			forwardData(data, addr)
			continue
		}

		var msg Message
		err = json.Unmarshal(decryptedData, &msg)
		if err != nil {
			fmt.Println("JSON unmarshal error:", err)
			continue
		}

		fmt.Println("Received message:", msg)

		// Log the message
		logMessage(msg)
	}
}

func decrypt(data []byte) ([]byte, error) {
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
	decryptedData, err := rsa.DecryptPKCS1v15(rand.Reader, rsaPrivateKey, data)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return decryptedData, nil
}

func forwardData(data []byte, senderAddr *net.UDPAddr) {
	mu.Lock()
	defer mu.Unlock()

	senderIP := senderAddr.IP.String()

	for _, target := range targets {
		if target != "" && !strings.Contains(target, ":") {
			target = target + ":42398"
		}

		if target != "" {
			udpAddr, err := net.ResolveUDPAddr("udp", target)
			if err != nil {
				fmt.Println("Forwarding error:", err)
				continue
			}

			// Compare the IP addresses
			if senderIP != udpAddr.IP.String() {
                                fmt.Printf("Relaying msg to %s\n", udpAddr.IP.String())
				conn, err := net.DialUDP("udp", nil, udpAddr)
				if err != nil {
					fmt.Println("Forwarding error:", err)
					continue
				}

				_, err = conn.Write(data)
				if err != nil {
					fmt.Println("Forwarding error:", err)
				}

				conn.Close()
			}
		}
	}
}

func logMessage(msg Message) {
	// TODO: Implement your logging logic here

        diff := time.Now().Unix() - msg.Timestamp
        duration := time.Duration(diff) * time.Second

        fmt.Printf(time.Now().String())
	fmt.Printf("\nLogged message: %+v\n", msg)

	fmt.Println("Time difference:", duration)
}

