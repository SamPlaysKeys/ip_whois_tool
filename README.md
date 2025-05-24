# IP WHOIS Lookup Tool

A Python command-line tool for looking up WHOIS information for IP addresses using multiple sources and methods. This tool helps network administrators, security professionals, and researchers gather information about IP addresses quickly and efficiently.

## Quick Start

```bash
# Install from PyPI
pip install ip-whois-tool

# Or install from source
git clone https://github.com/yourusername/ip_whois_tool.git
cd ip_whois_tool
pip install -e .

# Basic usage (both commands work the same)
ip-whois -i 8.8.8.8
ip-lookup -i 8.8.8.8
```

After installation, you can use either the `ip-whois` or `ip-lookup` command - they're aliases for the same functionality.

## Features

- **Multiple Resolver Methods**: Choose from IPWhois (RDAP), Python-WHOIS, or system whois command
- **Automatic Fallback**: When one method fails, automatically try others
- **Caching System**: Avoid repeated queries with built-in caching
- **Multiple Output Formats**: Export results as CSV, JSON, or formatted text
- **Parallel Processing**: Process multiple IP addresses simultaneously
- **Rich Console Output**: Colorful and well-formatted terminal output
- **Rate Limiting**: Respect WHOIS server limitations with configurable rate limiting

## Installation

### Prerequisites

- Python 3.8 or higher
- System whois command (optional, for system resolver)

### Installation Steps

```bash
# Clone the repository
git clone https://github.com/yourusername/ip_whois_tool.git
cd ip_whois_tool

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Make the script executable
chmod +x ip_lookup.py
```

## Usage

### Basic Usage

Look up a single IP address:

```bash
./ip_lookup.py -i 8.8.8.8
```

Look up multiple IP addresses:

```bash
./ip_lookup.py -i 8.8.8.8 -i 1.1.1.1 -i 9.9.9.9
```

Look up IP addresses from a file (one per line):

```bash
./ip_lookup.py -f ip_addresses.txt
```

### Output Options

Display results in the terminal:

```bash
./ip_lookup.py -i 8.8.8.8 -v  # Verbose output
```

Save results to a CSV file:

```bash
./ip_lookup.py -i 8.8.8.8 -o results.csv
```

Save results as JSON:

```bash
./ip_lookup.py -i 8.8.8.8 -o results.json --format json
```

Save results as formatted text:

```bash
./ip_lookup.py -i 8.8.8.8 -o results.txt --format text
```

### Lookup Options

Specify the lookup method:

```bash
./ip_lookup.py -i 8.8.8.8 --lookup-method ipwhois
./ip_lookup.py -i 8.8.8.8 --lookup-method pythonwhois
./ip_lookup.py -i 8.8.8.8 --lookup-method system
```

Force system whois command:

```bash
./ip_lookup.py -i 8.8.8.8 --force-system-whois
```

Disable caching:

```bash
./ip_lookup.py -i 8.8.8.8 --no-cache
```

Set custom timeout:

```bash
./ip_lookup.py -i 8.8.8.8 --timeout 15  # 15 seconds
```

### Performance Options

Disable parallel processing:

```bash
./ip_lookup.py -f ip_list.txt --no-parallel
```

Set maximum number of worker threads:

```bash
./ip_lookup.py -f ip_list.txt --max-workers 4
```

Clean expired cache entries:

```bash
./ip_lookup.py -i 8.8.8.8 --clean-cache
```

## Command-Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `-i`, `--ip` | IP address to look up (can be specified multiple times) | None |
| `-f`, `--file` | File containing IP addresses (one per line) | None |
| `-o`, `--output` | Output file path | None |
| `--format` | Output format (csv, json, text) | csv |
| `-v`, `--verbose` | Show verbose output | False |
| `--lookup-method` | WHOIS lookup method (auto, ipwhois, pythonwhois, system) | auto |
| `--force-system-whois` | Force use of system whois command | False |
| `--no-cache` | Disable caching of results | False |
| `--timeout` | Timeout for WHOIS lookups in seconds | 30.0 |
| `--rate-limit` | Minimum time between requests in seconds | 1.0 |
| `--no-parallel` | Disable parallel processing | False |
| `--max-workers` | Maximum number of worker threads | 8 |
| `--clean-cache` | Clean expired cache entries | False |

## Output Formats

### CSV Format

The CSV output includes the following columns:
- IP Address
- Organization
- Country
- City
- ASN
- Network
- Registration Date
- Source

### JSON Format

The JSON output includes all available data for each IP address, including:
- Basic information (IP, organization, location)
- Network details (ASN, network range)
- Registration information
- Source resolver

### Text Format

The text output provides a human-readable format with sections for each IP address, including:
- IP Address
- Organization
- Location (Country, City)
- Technical details (ASN, Network)
- Registration Date
- Source resolver

## Contributing

Contributions are welcome! Here's how you can contribute:

1. **Set up the development environment**:
   ```bash
   pip install -r requirements-dev.txt
   pre-commit install
   ```

2. **Make your changes**:
   - Fork the repository
   - Create a new branch (`git checkout -b feature/amazing-feature`)
   - Make your changes
   - Run tests (`pytest`)
   - Run linting (`ruff .`)

3. **Submit a pull request**:
   - Commit your changes (`git commit -m 'Add amazing feature'`)
   - Push to the branch (`git push origin feature/amazing-feature`)
   - Open a pull request

### Code Style

This project uses:
- Black for code formatting
- Ruff for linting
- Pre-commit hooks to enforce quality

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Example File

An example file (`example_ips.txt`) is included with well-known IP addresses that you can use to test the tool:

```bash
# Try the example file
./ip_lookup.py -f example_ips.txt

# Save results from example file
./ip_lookup.py -f example_ips.txt -o results.csv
```
