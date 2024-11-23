// args.go
package args

import (
	"flag"
	"fmt"
)

type Args struct {
	// NMB-specific flags
	NessusFilePath string
	ConfigFilePath string
	ProjectFolder  string
	NumWorkers     int

	// Remote connection flags
	RemoteHost string
	RemoteUser string
	RemotePass string
	RemoteKey  string

	// Nessus controller specific flags
	NessusMode  string
	PolicyPath  string
	TargetsFile string
	ExcludeFile string
	Discovery   bool
	ProjectName string

	// Plugin manager specific flags
	Plugin bool
}

func ParseArgs() *Args {
	args := &Args{}

	// NMB-specific flags
	flag.StringVar(&args.NessusFilePath, "nessus", "path/to/nessus.csv", "Path to the Nessus CSV file")
	flag.StringVar(&args.NessusFilePath, "n", "path/to/nessus.csv", "Path to the Nessus CSV file (short)")

	flag.StringVar(&args.ConfigFilePath, "config", "", "Path to the configuration file (optional)")
	flag.StringVar(&args.ConfigFilePath, "c", "", "Path to the configuration file (optional) (short)")

	flag.StringVar(&args.ProjectFolder, "project", "output", "Path to the project folder")
	flag.StringVar(&args.ProjectFolder, "p", "output", "Path to the project folder (short)")

	flag.IntVar(&args.NumWorkers, "workers", 10, "Number of concurrent workers")
	flag.IntVar(&args.NumWorkers, "w", 10, "Number of concurrent workers (short)")

	// Remote connection flags
	flag.StringVar(&args.RemoteHost, "remote", "", "Remote host to execute commands")
	flag.StringVar(&args.RemoteUser, "user", "", "Remote user for SSH connection")
	flag.StringVar(&args.RemotePass, "password", "", "Remote password for SSH connection")
	flag.StringVar(&args.RemoteKey, "key", "", "Path to SSH private key file (optional)")

	// Nessus controller flags
	flag.StringVar(&args.NessusMode, "mode", "", "Nessus operation mode (deploy, create, launch, monitor, pause, resume, export)")
	flag.StringVar(&args.PolicyPath, "policy", "", "Path to Nessus policy file (.nessus)")
	flag.StringVar(&args.TargetsFile, "targets", "", "Path to targets file")
	flag.StringVar(&args.ExcludeFile, "exclude", "", "Path to exclude targets file")
	flag.BoolVar(&args.Discovery, "discovery", false, "Enable host discovery scan")
	flag.StringVar(&args.ProjectName, "name", "", "Project name for the scan")

	// plugin manager
	flag.BoolVar(&args.Plugin, "plugin", false, "Enable plugin manager mode")

	// Custom usage message
	flag.Usage = customUsage

	flag.Parse()
	return args
}

func customUsage() {
	fmt.Printf("Usage: %s [options]\n\n", flag.CommandLine.Name())

	fmt.Println("NMB Mode Options:")
	fmt.Println("  -n, -nessus     Path to the Nessus CSV file")
	fmt.Println("  -c, -config     Path to the configuration file")
	fmt.Println("  -p, -project    Path to the project folder")
	fmt.Println("  -w, -workers    Number of concurrent workers")

	fmt.Println("\nRemote Connection Options:")
	fmt.Println("  -remote         Remote host to execute commands")
	fmt.Println("  -user           Remote user for SSH connection")
	fmt.Println("  -password       Remote password for SSH connection")
	fmt.Println("  -key            Path to SSH private key file")

	fmt.Println("\nNessus Controller Options:")
	fmt.Println("  -mode           Nessus operation mode (deploy, create, launch, monitor, pause, resume, export)")
	fmt.Println("  -policy         Path to Nessus policy file")
	fmt.Println("  -targets        Path to targets file")
	fmt.Println("  -exclude        Path to exclude targets file")
	fmt.Println("  -discovery      Enable host discovery scan")
	fmt.Println("  -name           Project name for the scan")

	fmt.Println("\nExamples:")
	fmt.Println("  NMB Mode:")
	fmt.Println("    program -nessus scan.csv -project ./output")
	fmt.Println("    program -n scan.csv -p ./output -w 20")

	fmt.Println("\n  Nessus Controller Mode:")
	fmt.Println("    program -mode deploy -remote 192.168.1.10 -user admin -password secret -name TestScan -targets hosts.txt")
	fmt.Println("    program -mode create -remote 192.168.1.10 -user admin -password secret -name TestScan -targets hosts.txt -discovery")
	fmt.Println("    program -mode launch -remote 192.168.1.10 -user admin -password secret -name TestScan")
}
