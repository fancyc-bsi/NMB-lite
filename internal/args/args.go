package args

import (
	"flag"
	"fmt"
)

type Args struct {
	NessusFilePath string
	ConfigFilePath string
	ProjectFolder  string
	NumWorkers     int
	RemoteHost     string
	RemoteUser     string
	RemotePass     string
	RemoteKey      string
}

func ParseArgs() *Args {
	nessusFilePath := flag.String("nessus", "path/to/nessus.csv", "Path to the Nessus CSV file")
	flag.StringVar(nessusFilePath, "n", *nessusFilePath, "Path to the Nessus CSV file (short)")

	configFilePath := flag.String("config", "", "Path to the configuration file (optional)")
	flag.StringVar(configFilePath, "c", *configFilePath, "Path to the configuration file (optional) (short)")

	projectFolder := flag.String("project", "output", "Path to the project folder")
	flag.StringVar(projectFolder, "p", *projectFolder, "Path to the project folder (short)")

	numWorkers := flag.Int("workers", 10, "Number of concurrent workers")
	flag.IntVar(numWorkers, "w", *numWorkers, "Number of concurrent workers (short)")

	// New SSH-related flags
	remoteHost := flag.String("remote", "", "Remote host to execute commands (optional)")
	remoteUser := flag.String("user", "", "Remote user for SSH connection")
	remotePass := flag.String("password", "", "Remote password for SSH connection")
	remoteKey := flag.String("key", "", "Path to SSH private key file (optional)")

	flag.Usage = func() {
		fmt.Printf("Usage: %s [options]\n", flag.CommandLine.Name())
		fmt.Println("Options:")
		flag.PrintDefaults()
	}

	flag.Parse()

	return &Args{
		NessusFilePath: *nessusFilePath,
		ConfigFilePath: *configFilePath,
		ProjectFolder:  *projectFolder,
		NumWorkers:     *numWorkers,
		RemoteHost:     *remoteHost,
		RemoteUser:     *remoteUser,
		RemotePass:     *remotePass,
		RemoteKey:      *remoteKey,
	}
}
