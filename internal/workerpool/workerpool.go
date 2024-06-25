package workerpool

import (
	"NMB/internal/nessus"
	"sync"
)

func StartWorkerPool(numWorkers int, findings []nessus.Finding, runScan func(wg *sync.WaitGroup, jobs <-chan nessus.Finding)) {
	var wg sync.WaitGroup
	jobs := make(chan nessus.Finding, len(findings))

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go runScan(&wg, jobs)
	}

	for _, finding := range findings {
		jobs <- finding
	}
	close(jobs)

	wg.Wait()
}
