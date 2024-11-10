package remote

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sync"

	"golang.org/x/crypto/ssh"
)

type RemoteExecutor struct {
	client    *ssh.Client
	mu        sync.Mutex
	connected bool
}

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

	return &RemoteExecutor{
		client:    client,
		connected: true,
	}, nil
}

func (r *RemoteExecutor) ExecuteCommand(command string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.connected {
		return "", fmt.Errorf("not connected to remote host")
	}

	session, err := r.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	var stdoutBuf, stderrBuf io.Writer
	stdoutBuf = new(bytes.Buffer)
	stderrBuf = new(bytes.Buffer)

	session.Stdout = stdoutBuf.(*bytes.Buffer)
	session.Stderr = stderrBuf.(*bytes.Buffer)

	err = session.Run(command)
	if err != nil {
		return "", fmt.Errorf("failed to run command: %v\nStderr: %s", err, stderrBuf.(*bytes.Buffer).String())
	}

	return stdoutBuf.(*bytes.Buffer).String(), nil
}

func (r *RemoteExecutor) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.connected {
		r.connected = false
		return r.client.Close()
	}
	return nil
}
