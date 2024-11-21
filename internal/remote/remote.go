package remote

import (
	"bytes"
	"fmt"
	"os"
	"sync"

	"golang.org/x/crypto/ssh"
)

type RemoteExecutor struct {
	client      *ssh.Client
	mu          sync.Mutex
	connected   bool
	sessionPool chan *ssh.Session
}

const (
	maxSessions = 10 // Maximum number of sessions in the pool
)

func NewRemoteExecutor(host, user, password, keyPath string) (*RemoteExecutor, error) {
	var authMethods []ssh.AuthMethod
	if password != "" {
		authMethods = append(authMethods, ssh.Password(password))
	}
	if keyPath != "" {
		key, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("unable to read private key: %v", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("unable to parse private key: %v", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}
	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no authentication methods provided")
	}

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", host), config)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %v", err)
	}

	executor := &RemoteExecutor{
		client:      client,
		connected:   true,
		sessionPool: make(chan *ssh.Session, maxSessions),
	}

	err = executor.initSessionPool()
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to initialize session pool: %v", err)
	}

	return executor, nil
}

func (r *RemoteExecutor) initSessionPool() error {
	for i := 0; i < maxSessions; i++ {
		session, err := r.client.NewSession()
		if err != nil {
			return fmt.Errorf("failed to create session: %v", err)
		}
		r.sessionPool <- session
	}
	return nil
}

func (r *RemoteExecutor) ExecuteCommand(command string) (string, error) {
	if !r.connected {
		return "", fmt.Errorf("not connected to remote host")
	}

	// Get session from pool
	session := <-r.sessionPool
	defer func() {
		// Return session to pool if it's still valid
		if session != nil {
			r.sessionPool <- session
		}
	}()

	var stdoutBuf, stderrBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf

	err := session.Run(command)
	if err != nil {
		// If session is broken, create a new one
		session.Close()
		newSession, createErr := r.client.NewSession()
		if createErr != nil {
			return "", fmt.Errorf("failed to create new session: %v", createErr)
		}
		session = newSession
		return "", fmt.Errorf("failed to run command: %v\nStderr: %s", err, stderrBuf.String())
	}

	return stdoutBuf.String(), nil
}

func (r *RemoteExecutor) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.connected {
		return nil
	}

	// Close all sessions in the pool
	for i := 0; i < maxSessions; i++ {
		session := <-r.sessionPool
		session.Close()
	}

	r.connected = false
	close(r.sessionPool)
	return r.client.Close()
}
