# Snort/Suricata Rules to NDJSON Converter

Convert Snort and Suricata intrusion detection system rules to NDJSON (Newline Delimited JSON) format for easy analysis, storage, and integration with modern data tools.

## 🚀 Quick Start

```bash
# 1. Save the converter code as main.go
# 2. Run the converter
go run main.go test.rules

# Output: Creates test.ndjson automatically
```

## 📋 Prerequisites

- Go 1.16 or later installed
- Snort/Suricata rules file

## 🔧 Installation

1. **Save the converter code** as `main.go` in your working directory
2. **Prepare your rules file** (e.g., `test.rules`, `snort.rules`, etc.)
3. **Run the converter** - that's it!

## 📖 Basic Usage

### Convert Rules File

```bash
go run main.go test.rules
```

**What happens:**
- Reads `test.rules` 
- Parses each Snort/Suricata rule
- Converts to structured JSON
- Saves as `test.ndjson`
- Shows progress: `"Converting test.rules -> test.ndjson"`

### File Naming Convention

The program automatically creates output files with `.ndjson` extension:

| Input File | Output File |
|------------|-------------|
| `test.rules` | `test.ndjson` |
| `snort.rules` | `snort.ndjson` |
| `my_rules.txt` | `my_rules.ndjson` |
| `detection_rules` | `detection_rules.ndjson` |

## 📊 Input Format

Your rules file should contain standard Snort/Suricata rules:

```
alert tcp $EXTERNAL_NET any -> $HOME_NET [139,445] (msg:"SERVER-SAMBA attack"; flow:to_server,established; content:"|FF|SMB"; sid:17152; rev:10;)
drop udp any any -> any 53 (msg:"DNS query blocked"; content:"malware.com"; sid:21164; rev:1;)
```

## 📄 Output Format

Each rule becomes a JSON object on its own line (NDJSON format):

```json
{"action":"alert","protocol":"tcp","source_ip":"$EXTERNAL_NET","source_port":"any","direction":"->","dest_ip":"$HOME_NET","dest_port":"[139,445]","options":{"msg":"SERVER-SAMBA attack","flow":"to_server,established","content":"|FF|SMB","sid":17152,"rev":10},"parsed_ports":{"destination_ports":["139","445"]},"metadata":{"sid":17152,"revision":10},"raw_rule":"alert tcp $EXTERNAL_NET any -> $HOME_NET [139,445] (msg:\"SERVER-SAMBA attack\"; flow:to_server,established; content:\"|FF|SMB\"; sid:17152; rev:10;)"}
```

## 🎛️ Command Options

### Basic Commands

```bash
# Standard conversion
go run main.go test.rules

# Pretty-print JSON (easier to read)
go run main.go -pretty test.rules

# Show help
go run main.go -help
```

### Advanced Options (Enhanced Version)

```bash
# Filter by specific SID
go run main.go -sid=17152 test.rules

# Exclude raw rule content (smaller file)
go run main.go -raw=false test.rules

# Combine options
go run main.go -pretty -sid=17152 test.rules
```

## ✅ Verify Output

### Quick Validation

```bash
# Check if valid NDJSON was created
cat test.ndjson | jq -c . > /dev/null && echo "✅ Valid NDJSON" || echo "❌ Invalid"

# Count records
echo "Rules converted: $(wc -l < test.ndjson)"

# File size
ls -lh test.ndjson
```

### View Content

```bash
# Show first record (pretty-printed)
head -1 test.ndjson | jq .

# Show all rule actions
cat test.ndjson | jq -r '.action' | sort | uniq -c

# Show all SIDs
cat test.ndjson | jq -r '.metadata.sid // .options.sid'
```

## 📁 Real Examples

### Single File Conversion

```bash
# Your Snort rules
go run main.go snort_rules.txt
# Creates: snort_rules.ndjson

# Your Suricata rules  
go run main.go suricata.rules
# Creates: suricata.ndjson

# Custom rules
go run main.go my_detection_rules.txt
# Creates: my_detection_rules.ndjson
```

### Batch Processing

```bash
# Convert all .rules files
for file in *.rules; do
    echo "Converting $file..."
    go run main.go "$file"
done

# Convert all .txt files
for file in *.txt; do
    echo "Processing $file..."
    go run main.go "$file"
done
```

## 🔍 Understanding the Output

### JSON Structure

Each converted rule contains:

```json
{
  "action": "alert",                    // Rule action (alert, drop, pass, reject)
  "protocol": "tcp",                    // Network protocol
  "source_ip": "$EXTERNAL_NET",         // Source IP/network
  "source_port": "any",                 // Source port(s)
  "direction": "->",                    // Traffic direction
  "dest_ip": "$HOME_NET",               // Destination IP/network
  "dest_port": "[139,445]",             // Destination port(s)
  "options": {                          // All rule options
    "msg": "Attack description",
    "sid": 17152,
    "rev": 10
  },
  "parsed_ports": {                     // Structured port info
    "destination_ports": ["139", "445"]
  },
  "metadata": {                         // Extracted metadata
    "sid": 17152,
    "revision": 10,
    "cves": ["2010-1635"],
    "severity": "attempted-dos"
  },
  "raw_rule": "original rule text..."   // Original rule
}
```

### Key Benefits

- **Structured data**: Easy to query and analyze
- **Preserved content**: Original rule text maintained
- **Extracted metadata**: CVEs, SIDs, references parsed
- **Type conversion**: Numbers as integers, proper data types
- **Port parsing**: Port ranges converted to arrays

## 🛠️ Use Cases

### 1. Security Analysis

```bash
# Convert rules
go run main.go security_rules.txt

# Analyze CVEs
cat security_rules.ndjson | jq -r '.metadata.cves[]?' | sort | uniq

# Count by severity
cat security_rules.ndjson | jq -r '.metadata.severity' | sort | uniq -c
```

### 2. Database Import

```bash
# Convert for database import
go run main.go rules.txt

# Import to MongoDB
mongoimport --db security --collection rules --file rules.ndjson

# Import to Elasticsearch
curl -X POST "localhost:9200/rules/_bulk" -H "Content-Type: application/json" --data-binary @rules.ndjson
```

### 3. Data Processing

```bash
# Convert rules
go run main.go detection_rules.txt

# Process with Python
python3 -c "
import json
with open('detection_rules.ndjson') as f:
    for line in f:
        rule = json.loads(line)
        print(f'SID {rule[\"metadata\"][\"sid\"]}: {rule[\"options\"][\"msg\"]}')
"
```

## 🐛 Troubleshooting

### Common Issues

**Error: "no such file or directory"**
```bash
# Make sure your rules file exists
ls -la test.rules

# Check you're in the right directory
pwd
```

**Error: "invalid rule format"**
```bash
# Check your rules file format
head -3 test.rules

# Look for parsing errors in output
go run main.go test.rules 2> errors.log
cat errors.log
```

**Empty output file**
```bash
# Check if input file has valid rules
grep -c "^alert\|^drop\|^pass" test.rules

# Verify rules aren't commented out
grep -v "^#" test.rules | head -3
```

### Validation

```bash
# Validate NDJSON format
jq -c . test.ndjson > /dev/null && echo "Valid JSON" || echo "Invalid JSON"

# Check record count matches input
echo "Input rules: $(grep -c '^alert\|^drop\|^pass\|^reject' test.rules)"
echo "Output records: $(wc -l < test.ndjson)"
```

## 📈 Performance

- **Speed**: Processes thousands of rules per second
- **Memory**: Efficient streaming processing
- **File size**: NDJSON typically 3-5x larger than original rules
- **Scalability**: Handles files with millions of rules

## 🔗 Integration Examples

### Kafka

```bash
go run main.go rules.txt
cat rules.ndjson | kafka-console-producer --topic security-rules --bootstrap-server localhost:9092
```

### Splunk

```bash
go run main.go rules.txt
# Import rules.ndjson into Splunk as JSON events
```

### Elastic Stack

```bash
go run main.go rules.txt
filebeat -e -c filebeat.yml  # Configure to read rules.ndjson
```

## 📚 Example Workflow

```bash
# 1. Convert your rules
go run main.go production_rules.txt

# 2. Verify output
echo "Converted $(wc -l < production_rules.ndjson) rules"

# 3. Quick analysis
echo "Rule types:"
cat production_rules.ndjson | jq -r '.action' | sort | uniq -c

echo "Top protocols:"
cat production_rules.ndjson | jq -r '.protocol' | sort | uniq -c | sort -nr | head -5

# 4. Ready for your data pipeline!
```

## 🆘 Support

If you encounter issues:

1. **Check input format**: Ensure rules follow Snort/Suricata syntax
2. **Verify Go installation**: `go version`
3. **Test with sample**: Create a simple test file with one rule
4. **Check permissions**: Ensure you can write to the output directory

## 📜 License

This tool is provided as-is for converting security rules to structured data format.

---

**Quick Reference:**
- Input: `.rules` or `.txt` files with Snort/Suricata rules
- Output: `.ndjson` files with structured JSON data
- Command: `go run main.go <input_file>`
- Result: Automatic creation of `<input_file>.ndjson`
