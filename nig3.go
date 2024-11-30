package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
  "github.com/pterm/pterm"
)
// Struktur untuk memetakan respons JSON
type ClaimResponse struct {
	Cell struct {
		Balance int64 `json:"balance"` // Field balance
	} `json:"cell"`
}
// Struktur untuk file JSON
type AuthorizationData struct {
	Authorizations []string `json:"authorizations"`
}

// Struktur data untuk memetakan JSON dari body
type Response struct {
	User struct {
		ID int64 `json:"ID"`
	} `json:"user"`
	Cell struct {
		StorageFillsAt string `json:"storage_fills_at"`
	} `json:"cell"`
}

// Fungsi untuk membaca authorization dari file
func readAuthorizations(filename string) ([]string, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var authData AuthorizationData
	err = json.Unmarshal(data, &authData)
	if err != nil {
		return nil, err
	}

	return authData.Authorizations, nil
}

// Fungsi untuk mem-parsing username dari authorization string
func parseUsername(auth string) string {
	start := strings.Index(auth, "%22username%22%3A%22") + len("%22username%22%3A%22")
	end := strings.Index(auth[start:], "%22")
	if start > len("%22username%22%3A%22")-1 && end != -1 {
		return auth[start : start+end]
	}
	return "unknown"
}

// Fungsi untuk mengklaim penyimpanan
// Fungsi untuk mengklaim penyimpanan
func cellClaim(auth string, spinner *pterm.SpinnerPrinter, username string) {
	url := "https://cellcoin.org/cells/claim_storage"
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		spinner.Fail("Error creating claim request: " + err.Error())
		return
	}

	req.Header.Add("Authorization", auth)
	resp, err := client.Do(req)
	if err != nil {
		spinner.Fail("Error sending claim request: " + err.Error())
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		spinner.Fail("Error reading claim response: " + err.Error())
		return
	}

	// Struktur untuk memetakan respons JSON
	var claimResponse ClaimResponse

	// Parsing JSON response
	err = json.Unmarshal(body, &claimResponse)
	if err != nil {
		spinner.Fail(fmt.Sprintf("[%s] Error parsing JSON: %s", username, err.Error()))
		return
	}

	// Ambil balance dari respons JSON
	balance := claimResponse.Cell.Balance

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted:
		spinner.Success(fmt.Sprintf("[%s] Claim successful, balance: %d (Status: %d)", username, balance, resp.StatusCode))
	case http.StatusUnauthorized:
		spinner.Fail(fmt.Sprintf("Unauthorized: Invalid authorization token (Status: %d)", resp.StatusCode))
	case http.StatusForbidden:
		spinner.Fail(fmt.Sprintf("Forbidden: Not allowed to claim storage (Status: %d)", resp.StatusCode))
	case http.StatusTooManyRequests:
		spinner.Fail(fmt.Sprintf("Rate limited: Too many requests (Status: %d)", resp.StatusCode))
	case http.StatusBadRequest:
		spinner.Fail(fmt.Sprintf("Bad request: %s (Status: %d)", string(body), resp.StatusCode))
	default:
		spinner.Fail(fmt.Sprintf("Claim failed with status code %d: %s", resp.StatusCode, string(body)))
	}
}

// Fungsi untuk menangani cell session setiap user
func cellSession(auth string, multi *pterm.MultiPrinter, wg *sync.WaitGroup) {
	defer wg.Done()
	username := parseUsername(auth)

	spinner, _ := pterm.DefaultSpinner.
		WithWriter(multi.NewWriter()).
		Start(fmt.Sprintf("[%s] Checking cell session...", username))

	url := "https://cellcoin.org/users/session"
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		spinner.Fail(fmt.Sprintf("[%s] Error creating request: %s", username, err.Error()))
		return
	}
	req.Header.Add("Authorization", auth)

	resp, err := client.Do(req)
	if err != nil {
		spinner.Fail(fmt.Sprintf("[%s] Error sending request: %s", username, err.Error()))
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		spinner.Fail(fmt.Sprintf("[%s] Error reading body: %s", username, err.Error()))
		return
	}

	var response Response
	err = json.Unmarshal(body, &response)
	if err != nil {
		spinner.Fail(fmt.Sprintf("[%s] Error parsing JSON: %s", username, err.Error()))
		return
	}

	storageFillsAt := response.Cell.StorageFillsAt
	targetTime, err := time.Parse(time.RFC3339, storageFillsAt)
	if err != nil {
		spinner.Fail(fmt.Sprintf("[%s] Error parsing time: %s", username, err.Error()))
		return
	}

	now := time.Now()
	for now.Before(targetTime) {
		remaining := targetTime.Sub(now).Truncate(time.Second)
		spinner.UpdateText(fmt.Sprintf("[%s] Time remaining: %s", username, remaining))
		time.Sleep(1 * time.Second)
		now = time.Now()
	}

	spinner.Success(fmt.Sprintf("[%s] Storage filled. Claiming...", username))
	cellClaim(auth, spinner, username)
}

func main() {
  fmt.Printf("\033[H\033[2J")
	authorizations, err := readAuthorizations("authorization.json")
	if err != nil {
		log.Fatalf("Error reading authorizations: %v", err)
	}

	var wg sync.WaitGroup
	multi := pterm.DefaultMultiPrinter

	for _, auth := range authorizations {
		wg.Add(1)
		go cellSession(auth, &multi, &wg)
	}

	multi.Start()
	wg.Wait()
	multi.Stop()
}
