# GhostMap: Mapping the Digital Shadows

GhostMap is an OSINT command-line tool designed to help penetration testers and security researchers passively gather domain information. It integrates with [crt.sh](https://crt.sh) for subdomain enumeration and [Shodan](https://www.shodan.io) for host information, enabling you to map out the digital footprint of a target quickly and effectively.

## Features

- **crt.sh Integration**: Enumerate subdomains using certificate transparency logs.
- **Shodan Integration**: Retrieve detailed host information for IP addresses associated with your target.
- **Configurable Shodan API Key**: Use the `init` command to securely store your Shodan API key for future use.
- **Flexible Output**: Display results in the terminal or save them as a JSON file.
- **Simple CLI Interface**: Easily use flags and options to customize your scan.

## Requirements

- Python 3.6 or higher
- The following Python dependencies (automatically installed):
  - `requests`

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/yourusername/ghostmap.git
   cd ghostmap

2. **Install the Package using pip:**

   ```bash
   pip install ghostmap
   ```

## Usage

### Initialize the Tool

Before scanning, you need to initialize the tool with your Shodan API key:

```bash
ghostmap init
```

You will be prompted to enter your Shodan API key. This key is stored securely in your home directory.

### Scanning


- Subdomain Enumeration Only:

```bash
ghostmap scan --domain example.com --crt
```

- Subdomain Enumeration and Shodan Host Information:


```bash
ghostmap scan --domain example.com --crt --shodan
```

- Combined Scan:

```bash
ghostmap scan --domain example.com
```

The Combined Scan will:
- Query crt.sh for subdomains
- Resolve IP addresses for each subdomain
- Query Shodan for each IP address
- Save the results to a JSON file


### Options

- `--crt`: Query crt.sh for subdomains
- `--shodan`: Query Shodan for each IP address
- `--shodan-key`: Optional: override stored Shodan API key
- `--output`: Output file to save JSON results


## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

GhostMap is intended for education and legal purposes only. Ensure you have the proper authorization before using this tool on any target.


















