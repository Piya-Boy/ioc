"""
Configuration settings for IOC Enrichment Tool
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# API Keys
API_KEYS = {
    'virustotal': os.getenv('VIRUSTOTAL_API_KEY'),
    'abuseipdb': os.getenv('ABUSEIPDB_API_KEY'),
    'otx': os.getenv('OTX_API_KEY'),
    'xforce': {
        'key': os.getenv('XFORCE_API_KEY'),
        'pass': os.getenv('XFORCE_API_PASS')
    },
    'shodan': os.getenv('SHODAN_API_KEY'),
    'hybrid_analysis': os.getenv('HYBRID_ANALYSIS_API_KEY')
}

# Scoring Configuration
SCORING = {
    'base_weights': {
        'sightings': 0.25,
        'freshness': 0.25,
        'source': 0.20,
        'context': 0.15,
        'accuracy': 0.15
    },
    'confidence_multipliers': {
        'high': 1.0,
        'medium': 0.8,
        'low': 0.6
    },
    'freshness_points': {
        '24h': 10,
        '7d': 5,
        '30d': -5
    },
    'source_tiers': {
        'tier1': 1.2,  # Government/Major Security Vendors
        'tier2': 1.0,  # Commercial TI Providers
        'tier3': 0.8   # Community/Open Source
    }
}

# Risk Levels
RISK_LEVELS = {
    'critical': (76, 100),
    'high': (51, 75),
    'medium': (26, 50),
    'low': (0, 25)
}

# MITRE ATT&CK Severity Multipliers
MITRE_SEVERITY = {
    'initial_access': 1.2,
    'execution': 1.1,
    'persistence': 1.3,
    'privilege_escalation': 1.4,
    'defense_evasion': 1.2,
    'credential_access': 1.3,
    'discovery': 1.0,
    'lateral_movement': 1.2,
    'collection': 1.1,
    'command_and_control': 1.4,
    'exfiltration': 1.3,
    'impact': 1.5
}

# Cache Settings
CACHE = {
    'enabled': True,
    'ttl': 3600,  # Time to live in seconds
    'max_size': 1000  # Maximum number of cached items
}

# Rate Limiting
RATE_LIMITS = {
    'virustotal': 4,  # requests per minute
    'abuseipdb': 45,  # requests per minute
    'otx': 60,       # requests per minute
    'xforce': 30,    # requests per minute
    'shodan': 1,     # requests per second
    'hybrid_analysis': 10  # requests per minute
}

# Logging Configuration
LOGGING = {
    'level': 'INFO',
    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    'file': 'ioc_enrichment.log'
}

# Supported IOC Types
IOC_TYPES = {
    'ipv4': r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$',
    'ipv6': r'^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$',
    'domain': r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$',
    'url': r'^https?://(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?:/[^\s]*)?$',
    'md5': r'^[a-fA-F0-9]{32}$',
    'sha1': r'^[a-fA-F0-9]{40}$',
    'sha256': r'^[a-fA-F0-9]{64}$',
    'sha512': r'^[a-fA-F0-9]{128}$',
    'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
    'registry': r'^HKEY_[A-Z_]+\\[\\\w\s.-]+$',
    'filepath': r'^[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*$'
} 