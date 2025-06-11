# IOC Enrichment Tool

A tool for enriching and analyzing Indicators of Compromise (IOCs) using multiple threat intelligence sources.

## Setup

1. Clone the repository:
```bash
git clone https://github.com/Piya-Boy/ioc.git
cd ioc
```

2. Create and activate virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
   - Copy `.env.example` to `.env`
   - Fill in your API keys in the `.env` file:
     ```
     VIRUSTOTAL_API_KEY=your_key_here
     ABUSEIPDB_API_KEY=your_key_here
     OTX_API_KEY=your_key_here
     XFORCE_API_KEY=your_key_here
     XFORCE_API_PASS=your_password_here
     SHODAN_API_KEY=your_key_here
     HYBRID_ANALYSIS_API_KEY=your_key_here
     ```

## Usage

[Add usage instructions here]

## API Keys Required

- VirusTotal
- AbuseIPDB
- OTX
- X-Force
- Shodan (optional)
- Hybrid Analysis (optional)

## Project Structure

- `main.py`: Main application file
- `config.py`: Configuration settings
- `utils.py`: Utility functions
- `requirements.txt`: Project dependencies

## License

[Add license information here] 