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
}

func ParseArgs() Args {
	nessusFilePath := flag.String("nessus", "path/to/nessus.csv", "Path to the Nessus CSV file")
	flag.StringVar(nessusFilePath, "n", *nessusFilePath, "Path to the Nessus CSV file (short)")

	configFilePath := flag.String("config", "", "Path to the configuration file (optional)")
	flag.StringVar(configFilePath, "c", *configFilePath, "Path to the configuration file (optional) (short)")

	projectFolder := flag.String("project", "output", "Path to the project folder")
	flag.StringVar(projectFolder, "p", *projectFolder, "Path to the project folder (short)")

	numWorkers := flag.Int("workers", 5, "Number of concurrent workers")
	flag.IntVar(numWorkers, "w", *numWorkers, "Number of concurrent workers (short)")

	flag.Usage = func() {
		fmt.Printf("Usage: %s [options]\n", flag.CommandLine.Name())
		fmt.Println("Options:")
		flag.PrintDefaults()
	}

	flag.Parse()

	return Args{
		NessusFilePath: *nessusFilePath,
		ConfigFilePath: *configFilePath,
		ProjectFolder:  *projectFolder,
		NumWorkers:     *numWorkers,
	}
}
