package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type EnhancedRule struct {
	Action      string                 `json:"action"`
	Protocol    string                 `json:"protocol"`
	SourceIP    string                 `json:"source_ip"`
	SourcePort  string                 `json:"source_port"`
	Direction   string                 `json:"direction"`
	DestIP      string                 `json:"dest_ip"`
	DestPort    string                 `json:"dest_port"`
	Options     map[string]interface{} `json:"options"`
	ParsedPorts *PortInfo             `json:"parsed_ports,omitempty"`
	Metadata    *RuleMetadata         `json:"metadata,omitempty"`
	RawRule     string                 `json:"raw_rule"`
}

type PortInfo struct {
	SourcePorts      []string `json:"source_ports,omitempty"`
	DestinationPorts []string `json:"destination_ports,omitempty"`
}

type RuleMetadata struct {
	CVEs       []string `json:"cves,omitempty"`
	References []string `json:"references,omitempty"`
	SID        int      `json:"sid,omitempty"`
	Revision   int      `json:"revision,omitempty"`
	Severity   string   `json:"severity,omitempty"`
}

var (
	prettyPrint = flag.Bool("pretty", false, "Pretty print JSON output")
	includeRaw  = flag.Bool("raw", true, "Include raw rule in output")
	filterSID   = flag.String("sid", "", "Filter by specific SID")
	helpFlag    = flag.Bool("help", false, "Show help")
)

func main() {
	flag.Parse()


	var filename string
	if flag.NArg() > 0 {
		filename = flag.Arg(0)
	} else {
		fmt.Println("Error: Please provide a rules file")
		fmt.Println("Usage: go run main.go <rules_file>")
		os.Exit(1)
	}

	file, err := os.Open(filename)
	if err != nil {
		log.Fatal("Error opening file:", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)

	outputFilename := generateOutputFilename(filename)
	
	outputWriter, err := os.Create(outputFilename)
	if err != nil {
		log.Fatal("Error creating output file:", err)
	}
	defer outputWriter.Close()
	
	log.Printf("Converting %s -> %s", filename, outputFilename)

	ruleCount := 0
	errorCount := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		rule, err := parseEnhancedRule(line)
		if err != nil {
			log.Printf("Error parsing rule %d: %v", ruleCount+1, err)
			errorCount++
			continue
		}

		if *filterSID != "" && rule.Metadata != nil {
			if strconv.Itoa(rule.Metadata.SID) != *filterSID {
				continue
			}
		}

		var jsonData []byte
		var jsonErr error

		if *prettyPrint {
			jsonData, jsonErr = json.MarshalIndent(rule, "", "  ")
		} else {
			jsonData, jsonErr = json.Marshal(rule)
		}

		if jsonErr != nil {
			log.Printf("Error marshaling to JSON: %v", jsonErr)
			errorCount++
			continue
		}

		fmt.Fprintln(outputWriter, string(jsonData))
		ruleCount++
	}

	if err := scanner.Err(); err != nil {
		log.Fatal("Error reading input:", err)
	}

	log.Printf("Successfully processed %d rules to %s", ruleCount, outputFilename)
	if errorCount > 0 {
		log.Printf("Processed %d rules successfully, %d errors", ruleCount, errorCount)
	}
}



func generateOutputFilename(inputFilename string) string {
	if lastDot := strings.LastIndex(inputFilename, "."); lastDot != -1 {
		if lastSlash := strings.LastIndex(inputFilename, "/"); lastSlash == -1 || lastDot > lastSlash {
			return inputFilename[:lastDot] + ".ndjson"
		}
	}
	return inputFilename + ".ndjson"
}

func parseEnhancedRule(line string) (*EnhancedRule, error) {
	ruleRegex := regexp.MustCompile(`^(\w+)\s+(\w+)\s+(\S+)\s+(\S+)\s+(-?>|<->|<-)\s+(\S+)\s+(\S+)\s+\((.+)\)$`)
	
	matches := ruleRegex.FindStringSubmatch(line)
	if len(matches) != 9 {
		return nil, fmt.Errorf("invalid rule format")
	}

	options := parseEnhancedOptions(matches[8])
	
	rule := &EnhancedRule{
		Action:     matches[1],
		Protocol:   matches[2],
		SourceIP:   matches[3],
		SourcePort: matches[4],
		Direction:  matches[5],
		DestIP:     matches[6],
		DestPort:   matches[7],
		Options:    options,
		ParsedPorts: parsePortInfo(matches[4], matches[7]),
		Metadata:   extractMetadata(options),
	}

	if *includeRaw {
		rule.RawRule = line
	}

	return rule, nil
}

func parseEnhancedOptions(optionsStr string) map[string]interface{} {
	options := make(map[string]interface{})
	
	parts := splitOptions(optionsStr)
	
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		colonIndex := strings.Index(part, ":")
		if colonIndex == -1 {
			options[part] = true
			continue
		}

		key := strings.TrimSpace(part[:colonIndex])
		value := strings.TrimSpace(part[colonIndex+1:])
		
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}

		if num, err := strconv.Atoi(value); err == nil {
			options[key] = num
		} else if num, err := strconv.ParseFloat(value, 64); err == nil {
			options[key] = num
		} else {
			options[key] = value
		}
	}

	return options
}

func parsePortInfo(sourcePort, destPort string) *PortInfo {
	info := &PortInfo{}
	
	if sourcePort != "any" {
		info.SourcePorts = parsePortString(sourcePort)
	}
	
	if destPort != "any" {
		info.DestinationPorts = parsePortString(destPort)
	}
	
	if len(info.SourcePorts) == 0 && len(info.DestinationPorts) == 0 {
		return nil
	}
	
	return info
}

func parsePortString(portStr string) []string {
	portStr = strings.Trim(portStr, "[]")
	
	ports := strings.Split(portStr, ",")
	var result []string
	
	for _, port := range ports {
		result = append(result, strings.TrimSpace(port))
	}
	
	return result
}

func extractMetadata(options map[string]interface{}) *RuleMetadata {
	metadata := &RuleMetadata{}
	
	if sid, exists := options["sid"]; exists {
		if sidInt, ok := sid.(int); ok {
			metadata.SID = sidInt
		} else if sidStr, ok := sid.(string); ok {
			if sidInt, err := strconv.Atoi(sidStr); err == nil {
				metadata.SID = sidInt
			}
		}
	}
	
	if rev, exists := options["rev"]; exists {
		if revInt, ok := rev.(int); ok {
			metadata.Revision = revInt
		} else if revStr, ok := rev.(string); ok {
			if revInt, err := strconv.Atoi(revStr); err == nil {
				metadata.Revision = revInt
			}
		}
	}
	
	if ref, exists := options["reference"]; exists {
		if refStr, ok := ref.(string); ok {
			if strings.HasPrefix(refStr, "cve,") {
				cve := strings.TrimPrefix(refStr, "cve,")
				metadata.CVEs = append(metadata.CVEs, cve)
			}
			metadata.References = append(metadata.References, refStr)
		}
	}
	
	if classtype, exists := options["classtype"]; exists {
		if classtypeStr, ok := classtype.(string); ok {
			metadata.Severity = classtypeStr
		}
	}
	
	if metadata.SID == 0 && metadata.Revision == 0 && len(metadata.CVEs) == 0 && 
	   len(metadata.References) == 0 && metadata.Severity == "" {
		return nil
	}
	
	return metadata
}

func splitOptions(optionsStr string) []string {
	var parts []string
	var current strings.Builder
	inQuotes := false
	
	for _, char := range optionsStr {
		switch char {
		case '"':
			inQuotes = !inQuotes
			current.WriteRune(char)
		case ';':
			if !inQuotes {
				parts = append(parts, current.String())
				current.Reset()
			} else {
				current.WriteRune(char)
			}
		default:
			current.WriteRune(char)
		}
	}
	
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}
	
	return parts
}
