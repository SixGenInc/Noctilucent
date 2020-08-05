package main

import (
	"crypto/tls"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Job holds the job ID and the domain to check
type Job struct {
	id     int
	domain string
}

// Result holds the job struct and a boolean indicating if the job.domain is frontable
type Result struct {
	job       Job
	frontable bool
}

var jobs = make(chan Job, 10)
var results = make(chan Result, 10)

func checkForCloudflareHeader(domain string) bool {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: time.Second * 10}
	req, err := http.NewRequest("GET", "https://"+domain, nil)
	req.Close = true
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		//log.Fatalln(err)
		//fmt.Printf("[E] %v\n", err)
		return false
	}

	for header, values := range resp.Header {
		// Check these three headers
		if strings.ToLower(header) == "server" ||
			strings.ToLower(header) == "set-cookie" ||
			strings.ToLower(header) == "expect-ct" {
			for _, value := range values {
				if strings.Contains(value, "cloudflare") || strings.Contains(value, "__cf") {
					//fmt.Println("[+] Found Cloudflare hosted site: " + domain)
					return true
				}
			}
		}
	}
	resp.Body.Close()
	return false
}

func worker(wg *sync.WaitGroup) {
	for job := range jobs {
		output := Result{job, checkForCloudflareHeader(job.domain)}
		results <- output
	}
	wg.Done()
}

func createWorkerPool(noOfWorkers int) {
	var wg sync.WaitGroup
	for i := 0; i < noOfWorkers; i++ {
		wg.Add(1)
		go worker(&wg)
	}
	wg.Wait()
	close(results)
}

func readCSV(filename string) {
	csvFile, _ := os.Open(filename)
	r := csv.NewReader(csvFile)

	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		i, _ := strconv.Atoi(record[0])
		job := Job{i, record[1]}
		jobs <- job
	}
	close(jobs)
}

func result(done chan bool) {
	for result := range results {
		// fmt.Printf("Job id %d, domain %s, frontable %t\n", result.job.id, result.job.domain, result.frontable)
		if result.frontable {
			// fmt.Println("[+] Found Cloudflare hosted site: " + result.job.domain)
			fmt.Println(result.job.domain)
		}
	}
	done <- true
}

func main() {
	startTime := time.Now()
	go readCSV("top-100k.csv")
	done := make(chan bool)
	go result(done)
	numberOfWorkers := 20
	createWorkerPool(numberOfWorkers)
	<-done
	endTime := time.Now()
	diff := endTime.Sub(startTime)
	fmt.Println("Total time taken: ", diff.Seconds(), "seconds")

}
