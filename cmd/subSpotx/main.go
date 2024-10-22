package main

import (
        "encoding/json"
        "flag"
        "fmt"
        "io/ioutil"
        "log"
        "net/http"
        "os"
        "strings"
        "time"

        "github.com/fatih/color"
)

type crtshEntry struct {
        CommonName string `json:"common_name"`
        NameValue  string `json:"name_value"`
}

type securityTrailsResponse struct {
        Subdomains []string `json:"subdomains"`
}

func printHelpMenu() {
        yellow := color.New(color.FgYellow).SprintFunc()
        turquoise := color.New(color.FgCyan).SprintFunc()
        gray := color.New(color.FgWhite).SprintFunc()
        end := color.New(color.Reset).SprintFunc()

        fmt.Println()
        fmt.Printf(" %sUsage: %s -d <domain> [-o <output file>]\n%s", yellow(" "), os.Args[0], end())
        fmt.Printf(" %sMenu options:\n", yellow(" "))
        fmt.Printf("    %s-d <domain>%s, %sSpecify the domain to scan for subdomains%s\n", turquoise(" "), end(), gray(" "), end())
        fmt.Printf("    %s-o <output file>%s, %sSave discovered subdomains to a specified file%s\n", turquoise(" "), end(), gray(" "), end())
        fmt.Printf("    %s-h%s, %sShow help menu%s\n\n", turquoise(" "), end(), gray(" "), end())
}

func getSubdomainsFromCrtSh(domain string) ([]string, error) {
        url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
        resp, err := http.Get(url)
        if err != nil {
                return nil, fmt.Errorf("HTTP request error")
        }
        defer resp.Body.Close()

        body, err := ioutil.ReadAll(resp.Body)
        if err != nil {
                return nil, fmt.Errorf("Error reading service response")
        }

        if strings.Contains(string(body), "<html") {
                return nil, nil
        }

        var entries []crtshEntry
        if err := json.Unmarshal(body, &entries); err != nil {
                return nil, fmt.Errorf("Error decoding response in JSON format")
        }

        subdomainsMap := make(map[string]bool)
        for _, entry := range entries {
                subdomains := strings.Split(entry.NameValue, "\n")
                for _, subdomain := range subdomains {
                        subdomain = strings.TrimSpace(subdomain)
                        if strings.HasSuffix(subdomain, domain) {
                                subdomainsMap[subdomain] = true
                        }
                }
        }

        var subdomains []string
        for subdomain := range subdomainsMap {
                subdomains = append(subdomains, subdomain)
        }

        return subdomains, nil
}

func getSubdomainsFromSecurityTrails(domain string) ([]string, error) {
        apiKey := "INSERT_YOUR_SECURITY_TRAILS_API_KEY"

        url := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains", domain)
        req, err := http.NewRequest("GET", url, nil)
        if err != nil {
                return nil, fmt.Errorf("HTTP request error")
        }

        req.Header.Add("APIKEY", apiKey)
        client := &http.Client{}
        resp, err := client.Do(req)
        if err != nil {
                return nil, fmt.Errorf("HTTP request to SecurityTrails failed")
        }
        defer resp.Body.Close()

        body, err := ioutil.ReadAll(resp.Body)
        if err != nil {
                return nil, fmt.Errorf("Error reading SecurityTrails response")
        }

        var secTrailsResponse securityTrailsResponse
        if err := json.Unmarshal(body, &secTrailsResponse); err != nil {
                return nil, fmt.Errorf("Error decoding the SecurityTrails JSON format response")
        }

        var subdomains []string
        for _, subdomain := range secTrailsResponse.Subdomains {
                subdomains = append(subdomains, subdomain+"."+domain)
        }

        return subdomains, nil
}

func mergeSubdomains(subdomains1, subdomains2 []string) []string {
        subdomainMap := make(map[string]bool)

        for _, subdomain := range subdomains1 {
                subdomainMap[subdomain] = true
        }
        for _, subdomain := range subdomains2 {
                subdomainMap[subdomain] = true
        }

        var mergedSubdomains []string
        for subdomain := range subdomainMap {
                mergedSubdomains = append(mergedSubdomains, subdomain)
        }

        return mergedSubdomains
}

func printBanner() {
        yellow := color.New(color.FgYellow).SprintFunc()
        turquoise := color.New(color.FgCyan).SprintFunc()
        blue := color.New(color.FgBlue).SprintFunc()

        fmt.Println()
        fmt.Println(yellow("                __   _____             __ "))
        fmt.Println(yellow("    _______  __/ /_ / ___/____  ____  / /__  __ "))
        fmt.Println(yellow("   / ___/ / / / __ \\___ \\/ __ \\/ __ \\/ __/ |/_/ "))
        fmt.Println(yellow("  (__  ) /_/ / /_/ /__/ / /_/ / /_/ / /__>  < "))
        fmt.Println(yellow(" /____/\\__,_/_.___/____/ .___/\\____/\\__/_/|_| "))
        fmt.Println(yellow("                      /_/ \n"))
        fmt.Println(turquoise("  Subdomain Discovery Tool"))
        fmt.Println(blue("  Version 1.0"))
                fmt.Println(turquoise("  Made by iTrox"))
        fmt.Println(blue("  subSpotx [-h] to view help menu"))
}

func handleFlags() (string, string) {
        domainPtr := flag.String("d", "", "Domain to scan")
        outputFilePtr := flag.String("o", "", "File to store the results")
        helpPtr := flag.Bool("h", false, "Show help menu")

        flag.Parse()

        if *helpPtr || *domainPtr == "" {
                printHelpMenu()
                os.Exit(0)
        }

        return *domainPtr, *outputFilePtr
}

func main() {
        domain, outputFile := handleFlags()

        printBanner()

        subdomainsCrtSh, err := getSubdomainsFromCrtSh(domain)
        if err != nil {
                log.Printf("Error getting subdomains from crt.sh")
        }

                subdomainsSecurityTrails, err := getSubdomainsFromSecurityTrails(domain)
        if err != nil {
                log.Printf("Error getting subdomains from Security Trails")
        }

        mergedSubdomains := mergeSubdomains(subdomainsCrtSh, subdomainsSecurityTrails)

        fmt.Printf("\nSubdomains discovered: %d\n\n", len(mergedSubdomains))
        time.Sleep(2 * time.Second)

        if len(mergedSubdomains) > 0 {
                fmt.Printf("Subdomains discovered for %s:\n", domain)
                for _, subdomain := range mergedSubdomains {
                        fmt.Println(subdomain)
                }
        } else {
                fmt.Printf("No subdomains found for the domain %s\n", domain)
        }

        if outputFile != "" {
                file, err := os.Create(outputFile)
                if err != nil {
                        log.Fatalf("Error creating the file: %v", err)
                }
                defer file.Close()

                for _, subdomain := range mergedSubdomains {
                        file.WriteString(subdomain + "\n")
                }
                fmt.Printf("\nSubdomains stored in the file %s\n", outputFile)
        }
}
