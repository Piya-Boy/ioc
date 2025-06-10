import streamlit as st
import pandas as pd
import math
from datetime import datetime
from io import StringIO
import requests
import json
from typing import Dict, Any, List, Optional
import concurrent.futures
from pathlib import Path

from config import (
    API_KEYS, SCORING, RISK_LEVELS, MITRE_SEVERITY,
    IOC_TYPES, CACHE, RATE_LIMITS
)
from utils import (
    validate_ioc, rate_limit, cache_result,
    calculate_freshness_score, format_stix_output,
    sanitize_filename, logger
)

# ========== Threat Intelligence Sources ==========
class ThreatIntelligence:
    def __init__(self, ioc: str):
        self.ioc = ioc
        self.ioc_type = validate_ioc(ioc)
        self.metrics = {
            'sightings': 0,
            'last_seen': datetime.utcnow(),
            'vt_score': 0,
            'abuse_score': 0,
            'otx_score': 0,
            'xforce_score': 0,
            'shodan_score': 0,
            'hybrid_score': 0,
            'context_score': 0.5,
            'accuracy_score': 0.8
        }
        self.country = "Unknown"
        self.types = []
        self.mitre_tactics = []
        self.references = {}

    @rate_limit('virustotal')
    @cache_result
    def check_virustotal(self) -> Dict[str, Any]:
        """Check VirusTotal for IOC information"""
        try:
            r = requests.get(
                f"https://www.virustotal.com/api/v3/search?query={self.ioc}",
                headers={"x-apikey": API_KEYS['virustotal']}
            )
            if r.ok and r.json().get("data"):
                attr = r.json()["data"][0]["attributes"]
                self.metrics['vt_score'] = min(attr["last_analysis_stats"]["malicious"], 10)
                self._update_last_seen(datetime.fromisoformat(attr.get("last_modification_date", datetime.utcnow().isoformat())))
                self.types.extend(attr.get("tags", []))
                self.references['virustotal'] = f"https://www.virustotal.com/gui/search/{self.ioc}"
        except Exception as e:
            logger.error(f"VirusTotal error: {e}")
        return self.metrics

    @rate_limit('abuseipdb')
    @cache_result
    def check_abuseipdb(self) -> Dict[str, Any]:
        """Check AbuseIPDB for IP reputation"""
        if self.ioc_type not in ['ipv4', 'ipv6']:
            return self.metrics
            
        try:
            r = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": API_KEYS['abuseipdb'], "Accept": "application/json"},
                params={"ipAddress": self.ioc, "maxAgeInDays": 90}
            )
            if r.ok:
                d = r.json()["data"]
                self.metrics['abuse_score'] = d.get("abuseConfidenceScore", 0) / 10
                self.types.append(d.get("usageType", ""))
                self.country = d.get("countryCode", self.country)
                self._update_last_seen(datetime.utcnow())
                self.references['abuseipdb'] = f"https://www.abuseipdb.com/check/{self.ioc}"
        except Exception as e:
            logger.error(f"AbuseIPDB error: {e}")
        return self.metrics

    @rate_limit('otx')
    @cache_result
    def check_otx(self) -> Dict[str, Any]:
        """Check AlienVault OTX for threat information"""
        try:
            r = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/{self.ioc_type}/{self.ioc}/general",
                headers={"X-OTX-API-KEY": API_KEYS['otx']}
            )
            if r.ok:
                data = r.json()
                pulses = len(data.get("pulse_info", {}).get("pulses", []))
                self.metrics['otx_score'] = min(pulses, 10)
                self._update_last_seen(datetime.utcnow())
                self.types.extend([p['name'] for p in data.get("pulse_info", {}).get("pulses", [])])
                self.references['otx'] = f"https://otx.alienvault.com/indicator/{self.ioc_type}/{self.ioc}"
        except Exception as e:
            logger.error(f"OTX error: {e}")
        return self.metrics

    @rate_limit('xforce')
    @cache_result
    def check_ibm_xforce(self) -> Dict[str, Any]:
        """Check IBM X-Force for threat intelligence"""
        try:
            r = requests.get(
                f"https://api.xforce.ibmcloud.com/{self.ioc_type}/{self.ioc}",
                auth=(API_KEYS['xforce']['key'], API_KEYS['xforce']['pass'])
            )
            if r.ok:
                d = r.json()
                self.metrics['xforce_score'] = d.get("score", 0)
                self._update_last_seen(datetime.utcnow())
                geo = d.get("geo", {})
                self.country = geo.get("country", self.country)
                self.types.extend(d.get("cats", {}).keys())
                self.references['xforce'] = f"https://exchange.xforce.ibmcloud.com/{self.ioc_type}/{self.ioc}"
        except Exception as e:
            logger.error(f"X-Force error: {e}")
        return self.metrics

    def _update_last_seen(self, seen: datetime):
        """Update last seen timestamp if newer"""
        if seen and seen > self.metrics['last_seen']:
            self.metrics['last_seen'] = seen

    def analyze(self) -> Dict[str, Any]:
        """Analyze IOC using all available sources"""
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(self.check_virustotal),
                executor.submit(self.check_abuseipdb),
                executor.submit(self.check_otx),
                executor.submit(self.check_ibm_xforce)
            ]
            concurrent.futures.wait(futures)

        # Calculate base score
        base_score = self._calculate_base_score()
        
        # Apply MITRE ATT&CK severity multiplier
        mitre_multiplier = self._get_mitre_multiplier()
        final_score = base_score * mitre_multiplier

        # Determine risk level
        risk_level = self._determine_risk_level(final_score)

        return {
            "IOC": self.ioc,
            "Type": self.ioc_type,
            "Score": round(final_score, 2),
            "Risk Level": risk_level,
            "Country": self.country,
            "Tags": ", ".join(set(t.lower() for t in self.types)),
            "MITRE Tactics": ", ".join(self.mitre_tactics),
            "References": self.references,
            **{f"{k.replace('_',' ').title()}": v for k, v in self.metrics.items()}
        }

    def _calculate_base_score(self) -> float:
        """Calculate base score using weighted metrics"""
        weights = SCORING['base_weights']
        
        # Normalize sightings
        s_norm = 1 / (1 + math.exp(-self.metrics['sightings'] / 10))
        
        # Calculate freshness score
        freshness = calculate_freshness_score(self.metrics['last_seen'])
        
        # Aggregate source scores
        src_raw = sum([
            self.metrics['vt_score'],
            self.metrics['abuse_score'],
            self.metrics['otx_score'],
            self.metrics['xforce_score']
        ]) / 40  # Normalize to 0-1

        # Calculate base score
        base = (
            weights['sightings'] * s_norm +
            weights['freshness'] * (freshness / 10) +
            weights['source'] * src_raw +
            weights['context'] * self.metrics['context_score'] +
            weights['accuracy'] * self.metrics['accuracy_score']
        )

        return base * 100

    def _get_mitre_multiplier(self) -> float:
        """Get MITRE ATT&CK severity multiplier"""
        if not self.mitre_tactics:
            return 1.0
            
        max_severity = max(
            MITRE_SEVERITY.get(tactic.lower(), 1.0)
            for tactic in self.mitre_tactics
        )
        return max_severity

    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level based on score"""
        for level, (min_score, max_score) in RISK_LEVELS.items():
            if min_score <= score <= max_score:
                return level.capitalize()
        return "Unknown"

# ========== STREAMLIT UI ==========
st.set_page_config(
    page_title="IOC Threat Analyzer",
    page_icon="🛡️",
    layout="wide"
)

# Custom CSS
st.markdown("""
    <style>
    .main {
        padding: 2rem;
    }
    .stButton>button {
        width: 100%;
    }
    .risk-critical { color: #ff4b4b; }
    .risk-high { color: #ffa726; }
    .risk-medium { color: #ffeb3b; }
    .risk-low { color: #66bb6a; }
    </style>
    """, unsafe_allow_html=True)

# Header
col1, col2 = st.columns([1, 3])
with col1:
    st.image("https://img.icons8.com/color/96/000000/shield.png", width=100)
with col2:
    st.title("IOC Threat Analyzer")
    st.markdown("Analyze and score potential threats using multiple threat intelligence sources")

# Input Section
st.markdown("---")
st.subheader("Input IOC Data")
col1, col2 = st.columns(2)

with col1:
    ioc_input = st.text_area(
        "Enter IOC (IP/URL/Hash)",
        height=150,
        placeholder="Enter one IOC per line..."
    )

with col2:
    uploaded_file = st.file_uploader(
        "Or upload a file",
        type=["csv", "txt"],
        help="Upload a CSV or TXT file with one IOC per line"
    )

# Process Input
ioc_list = []
if ioc_input:
    ioc_list = [l.strip() for l in ioc_input.splitlines() if l.strip()]
if uploaded_file:
    if uploaded_file.name.endswith(".csv"):
        df = pd.read_csv(uploaded_file)
        ioc_list += df.iloc[:,0].dropna().tolist()
    else:
        buf = StringIO(uploaded_file.getvalue().decode())
        ioc_list += [l.strip() for l in buf if l.strip()]

# Analysis Section
if ioc_list:
    st.markdown("---")
    st.subheader("Analysis Results")
    st.info(f"Analyzing {len(ioc_list)} IOCs...")
    
    results = []
    with st.spinner("Running threat analysis..."):
        for i in ioc_list:
            if not validate_ioc(i):
                st.warning(f"Invalid IOC format: {i}")
                continue
            ti = ThreatIntelligence(i)
            results.append(ti.analyze())

    if results:
        # Display Results
        df = pd.DataFrame(results)
        
        # Style the dataframe
        def highlight_risk(val):
            color = {
                'Critical': '#ff4b4b',
                'High': '#ffa726',
                'Medium': '#ffeb3b',
                'Low': '#66bb6a'
            }.get(val, '')
            return f'background-color: {color}'
        
        styled_df = df.style.applymap(highlight_risk, subset=['Risk Level'])
        st.dataframe(styled_df, use_container_width=True)
        
        # Export Options
        st.markdown("---")
        st.subheader("Export Results")
        col1, col2 = st.columns(2)
        
        with col1:
            # CSV Export
            csv = df.to_csv(index=False).encode("utf-8")
            st.download_button(
                "📥 Download CSV",
                csv,
                "ioc_results.csv",
                "text/csv",
                use_container_width=True
            )
        
        with col2:
            # STIX Export
            stix_data = [format_stix_output(r) for r in results]
            stix_json = json.dumps(stix_data, indent=2)
            st.download_button(
                "📥 Download STIX",
                stix_json,
                "ioc_results.stix",
                "application/json",
                use_container_width=True
            )
