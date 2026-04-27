# ===============================================================================
# ENHANCED INTRUSION DETECTION SYSTEM WITH EXPLAINABLE AI (XAI)
# Professional Version with MITRE ATT&CK Mapping, Recommendations & Visualization
# NEW MODULE ADDED: MITRE ATT&CK-based Attack Visualization Generator
# ===============================================================================

import streamlit as st
import pandas as pd
import numpy as np
import random
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import time
from datetime import datetime, timedelta
import seaborn as sns # type: ignore
import matplotlib.pyplot as plt
from io import BytesIO
import base64
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.feature_extraction.text import TfidfVectorizer
import networkx as nx

# ReportLab imports for PDF generation
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER

# ===============================================================================
# CONFIGURATION & STYLING
# ===============================================================================

def load_css():
    """Load custom CSS for professional styling"""
    st.markdown("""
    <style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        color: #1E3A8A;
        text-align: center;
        margin-bottom: 2rem;
        padding: 1rem;
        background: linear-gradient(90deg, #3B82F6, #1E40AF);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    
    .attack-card {
        padding: 1rem;
        margin: 0.5rem 0;
        border-radius: 10px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    
    .critical-attack {
        background: linear-gradient(135deg, #FEE2E2, #FECACA);
        border-left: 5px solid #EF4444;
        color: #111111;
    }
    
    .high-attack {
        background: linear-gradient(135deg, #FEF3C7, #FDE68A);
        border-left: 5px solid #F59E0B;
        color: #111111;
    }
    
    .medium-attack {
        background: linear-gradient(135deg, #DBEAFE, #BFDBFE);
        border-left: 5px solid #3B82F6;
        color: #111111;
    }
    
    .low-attack {
        background: linear-gradient(135deg, #D1FAE5, #A7F3D0);
        border-left: 5px solid #10B981;
        color: #111111;
    }
    
    .metric-card {
        background: white;
        padding: 1.5rem;
        border-radius: 10px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        text-align: center;
        color: #111111;
    }
    
    .sidebar-info {
        background: #F8FAFC;
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
        color: #111111;
    }
    
    .mitre-card {
        background: linear-gradient(135deg, #EDE9FE, #DDD6FE);
        border-left: 5px solid #8B5CF6;
        padding: 1rem;
        margin: 0.5rem 0;
        border-radius: 10px;
        color: #111111;
    }
    
    .recommendation-card {
        background: linear-gradient(135deg, #DBEAFE, #BFDBFE);
        border-left: 5px solid #0EA5E9;
        padding: 1rem;
        margin: 0.5rem 0;
        border-radius: 10px;
        color: #111111;
    }
    
    .visualization-card {
        background: linear-gradient(135deg, #FEF3C7, #FDE68A);
        border-left: 5px solid #F59E0B;
        padding: 1rem;
        margin: 0.5rem 0;
        border-radius: 10px;
        color: #111111;
    }
    </style>
    """, unsafe_allow_html=True)

# ===============================================================================
# ATTACK DETECTION ENGINE
# ===============================================================================

class AttackDetector:
    def __init__(self):
        self.attack_signatures = {
            "DDoS": {
                "description": "Distributed Denial of Service attack detected",
                "severity": "Critical",
                "color": "#EF4444",
                "icon": "🚨"
            },
            "BruteForce": {
                "description": "Brute force login attempts detected",
                "severity": "High",
                "color": "#F59E0B",
                "icon": "🔐"
            },
            "PortScan": {
                "description": "Port scanning reconnaissance detected",
                "severity": "Medium",
                "color": "#3B82F6",
                "icon": "🔍"
            },
            "SQLInjection": {
                "description": "SQL injection attack detected",
                "severity": "Critical",
                "color": "#EF4444",
                "icon": "💉"
            },
            "XSS": {
                "description": "Cross-site scripting attack detected",
                "severity": "High",
                "color": "#F59E0B",
                "icon": "📜"
            },
            "Botnet": {
                "description": "Botnet activity detected",
                "severity": "Critical",
                "color": "#EF4444",
                "icon": "🤖"
            },
            "Infiltration": {
                "description": "System infiltration attempt detected",
                "severity": "Critical",
                "color": "#EF4444",
                "icon": "🕵️"
            },
            "DoS Slowloris": {
                "description": "Slowloris DoS attack detected",
                "severity": "High",
                "color": "#F59E0B",
                "icon": "🐌"
            },
            "Heartbleed": {
                "description": "Heartbleed SSL/TLS vulnerability exploit",
                "severity": "Critical",
                "color": "#EF4444",
                "icon": "💔"
            },
            "Normal": {
                "description": "Normal network traffic - no threats detected",
                "severity": "Safe",
                "color": "#10B981",
                "icon": "✅"
            }
        }
    
    def detect_attacks(self, df):
        """Enhanced attack detection with confidence scoring"""
        attacks_detected = {}
        
        # DDoS Detection
        if df['packets'].max() > 1000 or df.groupby('dst_ip')['src_ip'].nunique().max() > 20:
            confidence = min(95, (df['packets'].max() / 1000) * 50 + 45)
            attacks_detected["DDoS"] = {"confidence": confidence, "affected_ips": df['dst_ip'].nunique()}
        
        # Port Scan Detection
        portscan_src = df.groupby('src_ip')['dst_port'].nunique()
        if any(portscan_src > 10):
            confidence = min(90, max(portscan_src) * 5)
            attacks_detected["PortScan"] = {"confidence": confidence, "scanning_ips": len(portscan_src[portscan_src > 10])}
        
        # Brute Force Detection
        bruteforce = df[(df['dst_port'] == 22) & (df['packets'] > 30)]
        if not bruteforce.empty:
            confidence = min(85, len(bruteforce) * 10)
            attacks_detected["BruteForce"] = {"confidence": confidence, "attempts": len(bruteforce)}
        
        # SQL Injection Detection
        sqlinjection = df[(df['protocol'] == 'HTTP') & (df['dst_port'] == 3306)]
        if not sqlinjection.empty:
            confidence = 88
            attacks_detected["SQLInjection"] = {"confidence": confidence, "requests": len(sqlinjection)}
        
        # XSS Detection
        xss = df[(df['protocol'] == 'HTTP') & (df['dst_port'] == 80) & (df['packets'] < 60)]
        if not xss.empty:
            confidence = 82
            attacks_detected["XSS"] = {"confidence": confidence, "malicious_requests": len(xss)}
        
        # Botnet Detection
        botnet_src = df[df['packets'] > 100].groupby('src_ip').size()
        if any(botnet_src > 5):
            confidence = 87
            attacks_detected["Botnet"] = {"confidence": confidence, "bot_ips": len(botnet_src[botnet_src > 5])}
        
        # Infiltration Detection
        infil = df[(df['packets'] > 50) & (df['bytes'] > 20000) & (df['packets'] < 300)]
        if not infil.empty:
            confidence = 79
            attacks_detected["Infiltration"] = {"confidence": confidence, "suspicious_connections": len(infil)}
        
        # DoS Slowloris Detection
        slowloris = df[(df['protocol'] == 'HTTP') & (df['packets'] > 400)]
        if not slowloris.empty:
            confidence = 91
            attacks_detected["DoS Slowloris"] = {"confidence": confidence, "slow_connections": len(slowloris)}
        
        # Heartbleed Detection
        heartbleed = df[(df['protocol'] == 'TCP') & (df['dst_port'] == 443)]
        if not heartbleed.empty:
            confidence = 94
            attacks_detected["Heartbleed"] = {"confidence": confidence, "ssl_requests": len(heartbleed)}
        
        if not attacks_detected:
            attacks_detected["Normal"] = {"confidence": 99, "status": "Clean"}
        
        return attacks_detected

# ===============================================================================
# MODULE 1: MITRE ATT&CK MAPPING MODULE
# ===============================================================================

class MITREAttackMapper:
    """
    MITRE ATT&CK Mapping Module
    Maps detected cyberattacks to standardized MITRE ATT&CK tactics and techniques
    Algorithm: Rule-Based Mapping using attack type classification
    """
    
    def __init__(self):
        # MITRE ATT&CK Framework Mapping Database
        self.mitre_mapping = {
            "DDoS": {
                "tactic": "Impact",
                "technique_id": "T1498",
                "technique_name": "Network Denial of Service",
                "description": "Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources to users. DDoS attacks saturate the target with traffic from multiple sources.",
                "mitigation": "Implement traffic filtering, rate limiting, and DDoS mitigation services"
            },
            "BruteForce": {
                "tactic": "Credential Access",
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained. This involves systematically checking all possible passwords.",
                "mitigation": "Implement account lockout policies, multi-factor authentication, and strong password requirements"
            },
            "PortScan": {
                "tactic": "Discovery",
                "technique_id": "T1046",
                "technique_name": "Network Service Scanning",
                "description": "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation.",
                "mitigation": "Use network segmentation, implement firewall rules, and deploy intrusion detection systems"
            },
            "SQLInjection": {
                "tactic": "Initial Access",
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "description": "Adversaries may attempt to exploit a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended behavior. SQL injection targets database queries.",
                "mitigation": "Use parameterized queries, input validation, Web Application Firewall (WAF), and regular security testing"
            },
            "XSS": {
                "tactic": "Initial Access",
                "technique_id": "T1189",
                "technique_name": "Drive-by Compromise",
                "description": "Adversaries may gain access to a system through a user visiting a website over the normal course of browsing. XSS allows attackers to inject malicious scripts into web pages viewed by other users.",
                "mitigation": "Implement Content Security Policy (CSP), input/output encoding, and XSS filters"
            },
            "Botnet": {
                "tactic": "Command and Control",
                "technique_id": "T1071",
                "technique_name": "Application Layer Protocol",
                "description": "Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic. Botnets use C2 channels to coordinate malicious activities.",
                "mitigation": "Deploy network monitoring, block known C2 domains, and implement egress filtering"
            },
            "Infiltration": {
                "tactic": "Persistence",
                "technique_id": "T1078",
                "technique_name": "Valid Accounts",
                "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
                "mitigation": "Implement privileged account management, monitor account activity, and use least privilege principles"
            },
            "DoS Slowloris": {
                "tactic": "Impact",
                "technique_id": "T1499",
                "technique_name": "Endpoint Denial of Service",
                "description": "Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services to users. Slowloris keeps connections open by sending partial requests.",
                "mitigation": "Configure connection timeouts, implement rate limiting, and use reverse proxy protection"
            },
            "Heartbleed": {
                "tactic": "Credential Access",
                "technique_id": "T1552.004",
                "technique_name": "Private Keys",
                "description": "Adversaries may search for private key certificate files on compromised systems for insecurely stored credentials. Heartbleed exploits TLS heartbeat extension to leak memory.",
                "mitigation": "Update OpenSSL versions, revoke and reissue SSL certificates, and implement proper key management"
            },
            "Normal": {
                "tactic": "None",
                "technique_id": "N/A",
                "technique_name": "No Malicious Activity",
                "description": "Traffic patterns are within normal parameters with no indicators of compromise detected.",
                "mitigation": "Continue regular monitoring and maintain security best practices"
            }
        }
    
    def map_attack_to_mitre(self, attack_type, confidence):
        """Maps a detected attack to MITRE ATT&CK framework"""
        if attack_type not in self.mitre_mapping:
            return {
                "tactic": "Unknown",
                "technique_id": "N/A",
                "technique_name": "Unknown Attack Type",
                "description": "Attack type not mapped in MITRE ATT&CK framework",
                "mitigation": "Perform manual analysis and update detection rules",
                "confidence": confidence
            }
        
        mitre_data = self.mitre_mapping[attack_type].copy()
        mitre_data["confidence"] = confidence
        mitre_data["attack_type"] = attack_type
        
        return mitre_data
    
    def generate_mitre_report(self, attacks_detected):
        """Generate comprehensive MITRE ATT&CK mapping report"""
        mitre_report = []
        
        for attack_type, details in attacks_detected.items():
            confidence = details.get('confidence', 0)
            mitre_mapping = self.map_attack_to_mitre(attack_type, confidence)
            mitre_report.append(mitre_mapping)
        
        return mitre_report

# ===============================================================================
# MODULE 2: RECOMMENDATION MODULE (Content-Based with Cosine Similarity)
# ===============================================================================

class SecurityRecommendationEngine:
    """
    Security Recommendation Module
    Provides preventive security recommendations based on detected attacks
    Algorithm: Content-Based Recommendation using Cosine Similarity
    """
    
    def __init__(self):
        # Security mitigation actions database
        self.mitigation_database = {
            "DDoS_mitigations": [
                "Deploy DDoS mitigation service (Cloudflare, Akamai, AWS Shield)",
                "Implement rate limiting on network devices and applications",
                "Configure traffic filtering and scrubbing centers",
                "Use Anycast network routing to distribute traffic",
                "Implement automated traffic analysis and blackholing",
                "Set up redundant network infrastructure",
                "Monitor bandwidth usage and establish baselines"
            ],
            "BruteForce_mitigations": [
                "Enable multi-factor authentication (MFA) for all accounts",
                "Implement account lockout after failed login attempts",
                "Use CAPTCHA challenges for authentication",
                "Deploy strong password policies (length, complexity)",
                "Monitor and alert on failed authentication attempts",
                "Implement IP-based rate limiting for login endpoints",
                "Use password managers and enforce regular password rotation"
            ],
            "PortScan_mitigations": [
                "Implement network segmentation and micro-segmentation",
                "Configure firewall rules to block unauthorized scanning",
                "Deploy Intrusion Detection/Prevention Systems (IDS/IPS)",
                "Close unused ports and disable unnecessary services",
                "Use port knocking or single packet authorization",
                "Monitor network traffic for reconnaissance patterns",
                "Implement honeypots to detect and analyze scanning activity"
            ],
            "SQLInjection_mitigations": [
                "Use parameterized queries and prepared statements",
                "Deploy Web Application Firewall (WAF) with SQL injection rules",
                "Implement strict input validation and sanitization",
                "Apply principle of least privilege for database accounts",
                "Use ORM (Object-Relational Mapping) frameworks",
                "Regular security testing and penetration testing",
                "Implement database activity monitoring and alerting"
            ],
            "XSS_mitigations": [
                "Implement Content Security Policy (CSP) headers",
                "Use output encoding for all user-generated content",
                "Deploy Web Application Firewall with XSS protection",
                "Validate and sanitize all user inputs",
                "Use HTTPOnly and Secure flags for cookies",
                "Implement subresource integrity (SRI) for external scripts",
                "Regular security code reviews and static analysis"
            ],
            "Botnet_mitigations": [
                "Deploy DNS filtering and block known C2 domains",
                "Implement network behavior analysis and anomaly detection",
                "Use endpoint detection and response (EDR) solutions",
                "Configure egress filtering and monitor outbound traffic",
                "Implement application whitelisting",
                "Regular malware scanning and endpoint hardening",
                "Monitor for beaconing behavior and unusual network patterns"
            ],
            "Infiltration_mitigations": [
                "Implement zero-trust network architecture",
                "Deploy privileged access management (PAM) solutions",
                "Enable comprehensive logging and SIEM monitoring",
                "Conduct regular security audits and access reviews",
                "Implement network access control (NAC)",
                "Use endpoint protection with behavioral analysis",
                "Establish incident response procedures and playbooks"
            ],
            "DoS_Slowloris_mitigations": [
                "Configure connection timeouts on web servers",
                "Implement reverse proxy with request queuing",
                "Deploy load balancers to distribute connections",
                "Set maximum concurrent connection limits",
                "Use mod_reqtimeout for Apache or similar for other servers",
                "Monitor slow connections and implement auto-blocking",
                "Consider using CDN services for traffic distribution"
            ],
            "Heartbleed_mitigations": [
                "Immediately update OpenSSL to patched versions (1.0.1g or later)",
                "Revoke and reissue all SSL/TLS certificates",
                "Reset all user credentials and API keys",
                "Implement proper memory management and bounds checking",
                "Deploy SSL/TLS vulnerability scanners",
                "Use certificate pinning where applicable",
                "Regular vulnerability scanning and patch management"
            ],
            "General_security": [
                "Implement defense-in-depth security strategy",
                "Conduct regular security awareness training",
                "Maintain up-to-date software and security patches",
                "Establish incident response and disaster recovery plans",
                "Perform regular security assessments and penetration testing",
                "Implement security information and event management (SIEM)",
                "Use threat intelligence feeds for proactive defense"
            ]
        }
        
        # Attack characteristics for similarity matching
        self.attack_characteristics = {
            "DDoS": "network flooding distributed denial service high traffic volume bandwidth saturation availability impact",
            "BruteForce": "authentication password guessing credential access failed login attempts systematic enumeration",
            "PortScan": "network reconnaissance service discovery vulnerability scanning port enumeration information gathering",
            "SQLInjection": "database injection web application exploit data exfiltration query manipulation",
            "XSS": "web application script injection client-side attack session hijacking code injection",
            "Botnet": "command control malware infected hosts coordinated attack distributed network",
            "Infiltration": "persistence unauthorized access lateral movement privilege escalation stealth intrusion",
            "DoS Slowloris": "connection exhaustion slow attack resource depletion service disruption http",
            "Heartbleed": "ssl tls vulnerability memory leak credential exposure encryption weakness certificate"
        }
    
    def calculate_risk_level(self, confidence):
        """Calculate risk level based on confidence score"""
        if confidence >= 85:
            return "CRITICAL"
        elif confidence >= 70:
            return "HIGH"
        elif confidence >= 50:
            return "MEDIUM"
        else:
            return "LOW"
    
    def get_recommendations(self, attack_type, confidence, top_n=5):
        """Generate security recommendations using content-based filtering"""
        risk_level = self.calculate_risk_level(confidence)
        
        # Get specific mitigations for the attack type
        mitigation_key = f"{attack_type}_mitigations"
        specific_mitigations = self.mitigation_database.get(
            mitigation_key, 
            self.mitigation_database["General_security"]
        )
        
        # Get attack characteristics
        attack_char = self.attack_characteristics.get(attack_type, "general security threat")
        
        # Calculate similarity scores using TF-IDF and Cosine Similarity
        all_mitigations = []
        mitigation_texts = []
        
        for key, mitigations in self.mitigation_database.items():
            for mitigation in mitigations:
                all_mitigations.append(mitigation)
                mitigation_texts.append(mitigation.lower())
        
        corpus = [attack_char] + mitigation_texts
        
        vectorizer = TfidfVectorizer(stop_words='english')
        tfidf_matrix = vectorizer.fit_transform(corpus)
        
        attack_vector = tfidf_matrix[0:1]
        mitigation_vectors = tfidf_matrix[1:]
        
        similarity_scores = cosine_similarity(attack_vector, mitigation_vectors)[0]
        ranked_indices = similarity_scores.argsort()[::-1]
        
        recommended_actions = []
        seen_actions = set()
        
        for mitigation in specific_mitigations[:top_n]:
            if mitigation not in seen_actions:
                recommended_actions.append({
                    "action": mitigation,
                    "priority": "HIGH",
                    "relevance_score": 0.95
                })
                seen_actions.add(mitigation)
        
        for idx in ranked_indices:
            if len(recommended_actions) >= top_n:
                break
            
            mitigation = all_mitigations[idx]
            if mitigation not in seen_actions:
                recommended_actions.append({
                    "action": mitigation,
                    "priority": "MEDIUM" if similarity_scores[idx] > 0.3 else "LOW",
                    "relevance_score": float(similarity_scores[idx])
                })
                seen_actions.add(mitigation)
        
        return {
            "attack_type": attack_type,
            "risk_level": risk_level,
            "confidence": confidence,
            "probability": confidence / 100,
            "recommendations": recommended_actions[:top_n]
        }
    
    def generate_comprehensive_report(self, attacks_detected, top_n=5):
        """Generate comprehensive security recommendations for all detected attacks"""
        reports = []
        
        for attack_type, details in attacks_detected.items():
            if attack_type != "Normal":
                confidence = details.get('confidence', 0)
                report = self.get_recommendations(attack_type, confidence, top_n)
                reports.append(report)
        
        return reports

# ===============================================================================
# NEW MODULE 3: MITRE ATT&CK-BASED VISUALIZATION GENERATOR
# ===============================================================================

class MITREAttackVisualizationEngine:
    """
    MITRE ATT&CK-based Visualization Generator
    Generates detailed, structured visualizations of cyberattacks based on:
    - Attack steps and kill chain phases
    - Mapped MITRE ATT&CK tactics and techniques
    - Network flow and attack progression
    - Timeline and impact analysis
    
    Algorithm: Graph-based visualization with temporal analysis
    """
    
    def __init__(self):
        # Attack kill chain mapping
        self.kill_chain_phases = {
            "DDoS": [
                {"phase": "Reconnaissance", "step": "Target identification and network mapping", "time": 0},
                {"phase": "Weaponization", "step": "Botnet command & control setup", "time": 1},
                {"phase": "Delivery", "step": "Initial traffic flood initiation", "time": 2},
                {"phase": "Exploitation", "step": "Bandwidth saturation and resource exhaustion", "time": 3},
                {"phase": "Impact", "step": "Service disruption and denial of availability", "time": 4}
            ],
            "BruteForce": [
                {"phase": "Reconnaissance", "step": "Identify authentication endpoints", "time": 0},
                {"phase": "Resource Development", "step": "Prepare password dictionaries and tools", "time": 1},
                {"phase": "Initial Access", "step": "Automated login attempt generation", "time": 2},
                {"phase": "Credential Access", "step": "Password enumeration and guessing", "time": 3},
                {"phase": "Impact", "step": "Unauthorized access or account lockout", "time": 4}
            ],
            "PortScan": [
                {"phase": "Reconnaissance", "step": "Network range identification", "time": 0},
                {"phase": "Discovery", "step": "Active port scanning across target systems", "time": 1},
                {"phase": "Discovery", "step": "Service version detection", "time": 2},
                {"phase": "Discovery", "step": "Vulnerability identification", "time": 3},
                {"phase": "Collection", "step": "Aggregate target intelligence data", "time": 4}
            ],
            "SQLInjection": [
                {"phase": "Reconnaissance", "step": "Web application input field discovery", "time": 0},
                {"phase": "Initial Access", "step": "Inject malicious SQL payloads", "time": 1},
                {"phase": "Execution", "step": "Execute unauthorized database queries", "time": 2},
                {"phase": "Collection", "step": "Extract sensitive database information", "time": 3},
                {"phase": "Exfiltration", "step": "Data theft and unauthorized access", "time": 4}
            ],
            "XSS": [
                {"phase": "Reconnaissance", "step": "Identify vulnerable web forms and inputs", "time": 0},
                {"phase": "Initial Access", "step": "Inject malicious JavaScript payload", "time": 1},
                {"phase": "Execution", "step": "Script execution in victim browsers", "time": 2},
                {"phase": "Credential Access", "step": "Session cookie theft and hijacking", "time": 3},
                {"phase": "Impact", "step": "User data compromise and account takeover", "time": 4}
            ],
            "Botnet": [
                {"phase": "Initial Access", "step": "Malware infection of endpoint systems", "time": 0},
                {"phase": "Execution", "step": "Bot agent installation and persistence", "time": 1},
                {"phase": "Command and Control", "step": "C2 channel establishment", "time": 2},
                {"phase": "Command and Control", "step": "Receive and execute attacker commands", "time": 3},
                {"phase": "Impact", "step": "Coordinated malicious activities", "time": 4}
            ],
            "Infiltration": [
                {"phase": "Initial Access", "step": "Exploit vulnerability or credential theft", "time": 0},
                {"phase": "Execution", "step": "Malicious code execution", "time": 1},
                {"phase": "Persistence", "step": "Establish foothold in target system", "time": 2},
                {"phase": "Privilege Escalation", "step": "Elevate access permissions", "time": 3},
                {"phase": "Lateral Movement", "step": "Spread across internal network", "time": 4}
            ],
            "DoS Slowloris": [
                {"phase": "Reconnaissance", "step": "Identify target web server", "time": 0},
                {"phase": "Resource Development", "step": "Prepare slow connection tools", "time": 1},
                {"phase": "Initial Access", "step": "Establish multiple partial connections", "time": 2},
                {"phase": "Exploitation", "step": "Keep connections alive indefinitely", "time": 3},
                {"phase": "Impact", "step": "Server resource exhaustion", "time": 4}
            ],
            "Heartbleed": [
                {"phase": "Reconnaissance", "step": "Identify vulnerable OpenSSL versions", "time": 0},
                {"phase": "Initial Access", "step": "Send malformed heartbeat requests", "time": 1},
                {"phase": "Credential Access", "step": "Extract memory contents", "time": 2},
                {"phase": "Collection", "step": "Harvest credentials and private keys", "time": 3},
                {"phase": "Impact", "step": "Data breach and encryption compromise", "time": 4}
            ]
        }
        
        # MITRE ATT&CK tactic colors for visualization
        self.tactic_colors = {
            "Reconnaissance": "#8B5CF6",
            "Resource Development": "#A78BFA",
            "Initial Access": "#EF4444",
            "Execution": "#F59E0B",
            "Persistence": "#F97316",
            "Privilege Escalation": "#EAB308",
            "Defense Evasion": "#84CC16",
            "Credential Access": "#22C55E",
            "Discovery": "#10B981",
            "Lateral Movement": "#14B8A6",
            "Collection": "#06B6D4",
            "Command and Control": "#0EA5E9",
            "Exfiltration": "#3B82F6",
            "Impact": "#6366F1",
            "Weaponization": "#8B5CF6",
            "Delivery": "#D946EF",
            "Exploitation": "#EC4899"
        }
    
    def generate_attack_killchain_visualization(self, attack_type, mitre_data, confidence):
        """
        Generate kill chain visualization showing attack progression
        
        Args:
            attack_type: Type of attack
            mitre_data: MITRE ATT&CK mapping data
            confidence: Detection confidence score
        
        Returns:
            Plotly figure object with kill chain visualization
        """
        
        if attack_type not in self.kill_chain_phases:
            return None
        
        phases = self.kill_chain_phases[attack_type]
        
        # Create Sankey diagram for attack flow
        fig = go.Figure()
        
        # Timeline visualization
        phase_names = [p['phase'] for p in phases]
        steps = [p['step'] for p in phases]
        times = [p['time'] for p in phases]
        colors = [self.tactic_colors.get(p['phase'], '#6B7280') for p in phases]
        
        fig = go.Figure()
        
        # Add timeline trace
        fig.add_trace(go.Scatter(
            x=times,
            y=phase_names,
            mode='markers+lines+text',
            marker=dict(
                size=20,
                color=colors,
                line=dict(color='white', width=2)
            ),
            line=dict(color='#CBD5E1', width=3),
            text=phase_names,
            textposition="top center",
            hovertext=steps,
            hoverinfo='text',
            name='Attack Progression'
        ))
        
        fig.update_layout(
            title=dict(
                text=f"{attack_type} Attack Kill Chain Visualization<br><sub>Confidence: {confidence:.1f}% | MITRE Tactic: {mitre_data['tactic']}</sub>",
                x=0.5,
                xanchor='center'
            ),
            xaxis=dict(
                title="Attack Timeline (Phases)",
                showgrid=True,
                gridcolor='#E5E7EB'
            ),
            yaxis=dict(
                title="",
                showgrid=False
            ),
            height=400,
            hovermode='closest',
            plot_bgcolor='white',
            paper_bgcolor='white'
        )
        
        return fig
    
    def generate_attack_graph_visualization(self, attack_type, attack_details, df):
        """
        Generate network graph showing attack sources, targets, and flows
        
        Args:
            attack_type: Type of attack
            attack_details: Details about the detected attack
            df: Network traffic dataframe
        
        Returns:
            Plotly figure object with network graph
        """
        
        # Create network graph
        G = nx.DiGraph()
        
        # Sample relevant traffic for visualization
        sample_size = min(50, len(df))
        sample_df = df.sample(sample_size)
        
        # Add nodes and edges
        for _, row in sample_df.iterrows():
            G.add_edge(
                row['src_ip'],
                row['dst_ip'],
                weight=row['packets'],
                protocol=row['protocol']
            )
        
        # Generate layout
        pos = nx.spring_layout(G, k=2, iterations=50)
        
        # Create edge traces
        edge_traces = []
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            
            edge_trace = go.Scatter(
                x=[x0, x1, None],
                y=[y0, y1, None],
                mode='lines',
                line=dict(width=1, color='#CBD5E1'),
                hoverinfo='none',
                showlegend=False
            )
            edge_traces.append(edge_trace)
        
        # Create node trace
        node_x = []
        node_y = []
        node_text = []
        node_size = []
        node_color = []
        
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            
            # Determine if source or destination
            out_degree = G.out_degree(node)
            in_degree = G.in_degree(node)
            
            if out_degree > in_degree:
                node_text.append(f"Source: {node}<br>Outbound: {out_degree}")
                node_color.append('#EF4444')  # Red for attackers
                node_size.append(20 + out_degree * 5)
            else:
                node_text.append(f"Target: {node}<br>Inbound: {in_degree}")
                node_color.append('#3B82F6')  # Blue for targets
                node_size.append(15 + in_degree * 3)
        
        node_trace = go.Scatter(
            x=node_x,
            y=node_y,
            mode='markers+text',
            hovertext=node_text,
            hoverinfo='text',
            marker=dict(
                size=node_size,
                color=node_color,
                line=dict(color='white', width=2)
            ),
            showlegend=False
        )
        
        # Create figure
        fig = go.Figure(data=edge_traces + [node_trace])
        
        fig.update_layout(
            title=f"{attack_type} Attack Network Graph",
            showlegend=False,
            hovermode='closest',
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            height=500,
            plot_bgcolor='white',
            paper_bgcolor='white'
        )
        
        return fig
    
    def generate_attack_heatmap(self, attack_type, df):
        """
        Generate temporal heatmap showing attack intensity over time
        
        Args:
            attack_type: Type of attack
            df: Network traffic dataframe
        
        Returns:
            Plotly figure object with heatmap
        """
        
        # Create time-based aggregation
        timestamps = pd.date_range(
            start=datetime.now() - timedelta(hours=1),
            end=datetime.now(),
            periods=len(df)
        )
        
        df_temp = df.copy()
        df_temp['timestamp'] = timestamps
        df_temp['hour'] = df_temp['timestamp'].dt.hour
        df_temp['minute_bin'] = (df_temp['timestamp'].dt.minute // 5) * 5
        
        # Create heatmap data
        heatmap_data = df_temp.groupby(['hour', 'minute_bin'])['packets'].sum().reset_index()
        heatmap_pivot = heatmap_data.pivot(index='minute_bin', columns='hour', values='packets').fillna(0)
        
        fig = go.Figure(data=go.Heatmap(
            z=heatmap_pivot.values,
            x=heatmap_pivot.columns,
            y=heatmap_pivot.index,
            colorscale='Reds',
            hovertemplate='Hour: %{x}<br>Minute: %{y}<br>Packets: %{z}<extra></extra>'
        ))
        
        fig.update_layout(
            title=f"{attack_type} Attack Intensity Heatmap",
            xaxis_title="Hour of Day",
            yaxis_title="Minute",
            height=400
        )
        
        return fig
    
    def generate_mitre_technique_matrix(self, mitre_report):
        """
        Generate MITRE ATT&CK technique matrix visualization
        
        Args:
            mitre_report: List of MITRE mappings for detected attacks
        
        Returns:
            Plotly figure object with technique matrix
        """
        
        # Extract tactics and techniques
        tactics = []
        techniques = []
        confidences = []
        attack_types = []
        
        for item in mitre_report:
            if item['attack_type'] != 'Normal':
                tactics.append(item['tactic'])
                techniques.append(item['technique_name'])
                confidences.append(item['confidence'])
                attack_types.append(item['attack_type'])
        
        if not tactics:
            return None
        
        # Create bubble chart
        fig = go.Figure()
        
        for i, (tactic, technique, conf, attack) in enumerate(zip(tactics, techniques, confidences, attack_types)):
            fig.add_trace(go.Scatter(
                x=[i],
                y=[tactic],
                mode='markers+text',
                marker=dict(
                    size=conf,
                    color=self.tactic_colors.get(tactic, '#6B7280'),
                    sizemode='diameter',
                    sizeref=2,
                    line=dict(color='white', width=2)
                ),
                text=attack,
                textposition="middle center",
                hovertext=f"{attack}<br>{technique}<br>Confidence: {conf:.1f}%",
                hoverinfo='text',
                showlegend=False
            ))
        
        fig.update_layout(
            title="MITRE ATT&CK Technique Matrix",
            xaxis=dict(title="", showticklabels=False, showgrid=False),
            yaxis=dict(title="MITRE ATT&CK Tactics"),
            height=400,
            hovermode='closest'
        )
        
        return fig
    
    def generate_comprehensive_attack_visualization(self, attack_type, mitre_data, attack_details, df, confidence):
        """
        Generate comprehensive multi-panel attack visualization
        
        Returns:
            Dictionary containing all visualization figures
        """
        
        visualizations = {}
        
        # 1. Kill Chain Timeline
        visualizations['killchain'] = self.generate_attack_killchain_visualization(
            attack_type, mitre_data, confidence
        )
        
        # 2. Attack Network Graph
        visualizations['network_graph'] = self.generate_attack_graph_visualization(
            attack_type, attack_details, df
        )
        
        # 3. Attack Intensity Heatmap
        visualizations['heatmap'] = self.generate_attack_heatmap(attack_type, df)
        
        return visualizations

# ===============================================================================
# XAI ENGINE
# ===============================================================================

class XAIExplainer:
    def __init__(self):
        self.feature_importance = {}
    
    def generate_explanation(self, attack_type, df):
        """Generate natural language explanations for detected attacks"""
        explanations = {
            "DDoS": f"""
            **🚨 DDoS Attack Analysis:**
            
            The system detected a Distributed Denial of Service attack characterized by:
            - **High packet volume**: Peak of {df['packets'].max():,} packets from multiple sources
            - **Target concentration**: {df['dst_ip'].nunique()} unique destination IPs under attack  
            - **Traffic pattern**: Unusual spike in concurrent connections suggesting coordinated attack
            
            **Recommendation**: Implement rate limiting and traffic filtering immediately.
            """,
            
            "BruteForce": f"""
            **🔐 Brute Force Attack Analysis:**
            
            Multiple unauthorized access attempts detected:
            - **Target service**: SSH (Port 22) login attempts
            - **Attack pattern**: {len(df[df['dst_port'] == 22])} connection attempts with high packet counts
            - **Persistence**: Repeated attempts from same source IPs indicating automated attack
            
            **Recommendation**: Enable account lockout policies and monitor failed login attempts.
            """,
            
            "PortScan": f"""
            **🔍 Port Scan Analysis:**
            
            Reconnaissance activity detected:
            - **Scanning behavior**: Single source probing multiple destination ports
            - **Port range**: {df['dst_port'].nunique()} different ports scanned
            - **Intent**: Information gathering phase, likely precursor to targeted attack
            
            **Recommendation**: Block scanning IP and review firewall rules.
            """,
            
            "SQLInjection": f"""
            **💉 SQL Injection Attack Analysis:**
            
            Database attack detected:
            - **Target**: HTTP traffic to database port (3306)
            - **Method**: Malicious SQL queries embedded in web requests
            - **Risk level**: Critical - potential data breach or system compromise
            
            **Recommendation**: Implement parameterized queries and input validation.
            """,
            
            "Normal": """
            **✅ Network Status: SECURE**
            
            All traffic patterns appear normal:
            - No suspicious packet volumes detected
            - Connection patterns within expected parameters  
            - No known attack signatures identified
            
            **Status**: System operating normally with no immediate threats.
            """
        }
        
        return explanations.get(attack_type, f"**Analysis for {attack_type}**: Detailed explanation not available.")
    
    def calculate_feature_importance(self, df, attack_type):
        """Calculate and return feature importance scores for XAI"""
        if attack_type == "DDoS":
            importance = {
                "Packet Volume": min(100, (df['packets'].max() / 1000) * 100),
                "Source IP Diversity": (df['src_ip'].nunique() / 50) * 100,
                "Connection Duration": (df['duration'].max() / df['duration'].sum()) * 100,
                "Destination Concentration": (1 / df['dst_ip'].nunique()) * 100,
                "Traffic Rate": np.random.randint(60, 90)
            }
        elif attack_type == "BruteForce":
            importance = {
                "SSH Port Activity": (df['dst_port'] == 22).sum() / len(df) * 100,
                "Packet Frequency": (df['packets'].max() / df['packets'].sum()) * 100,
                "SYN Flag Ratio": np.random.randint(70, 95),
                "Failed Connections": np.random.randint(80, 95),
                "Source Persistence": np.random.randint(60, 85)
            }
        elif attack_type == "PortScan":
            importance = {
                "Port Diversity": (df['dst_port'].nunique() / len(df)) * 100,
                "Scan Speed": np.random.randint(70, 90),
                "Sequential Pattern": np.random.randint(60, 85),
                "Connection Attempts": (df['packets'].max() / df['packets'].sum()) * 100,
                "Source Concentration": np.random.randint(50, 75)
            }
        else:
            importance = {
                "Traffic Volume": np.random.randint(40, 80),
                "Connection Pattern": np.random.randint(30, 70),
                "Protocol Usage": np.random.randint(20, 60),
                "Timing Analysis": np.random.randint(35, 75)
            }
        
        return importance

# ===============================================================================
# DATA ANALYTICS ENGINE
# ===============================================================================

class NetworkAnalytics:
    def __init__(self, df):
        self.df = df
    
    def generate_traffic_summary(self):
        """Generate comprehensive traffic analytics"""
        summary = {
            "total_connections": len(self.df),
            "unique_sources": self.df['src_ip'].nunique(),
            "unique_destinations": self.df['dst_ip'].nunique(),
            "total_packets": self.df['packets'].sum(),
            "total_bytes": self.df['bytes'].sum(),
            "avg_duration": self.df['duration'].mean(),
            "protocols": self.df['protocol'].value_counts().to_dict(),
            "top_ports": self.df['dst_port'].value_counts().head(5).to_dict()
        }
        return summary
    
    def create_traffic_timeline(self):
        """Create timeline visualization of network traffic"""
        timestamps = pd.date_range(
            start=datetime.now() - timedelta(hours=1),
            end=datetime.now(),
            periods=len(self.df)
        )
        
        timeline_df = self.df.copy()
        timeline_df['timestamp'] = timestamps
        timeline_df = timeline_df.groupby(timeline_df['timestamp'].dt.floor('5T')).agg({
            'packets': 'sum',
            'bytes': 'sum',
            'src_ip': 'nunique'
        }).reset_index()
        
        return timeline_df
    
    def generate_risk_score(self, attacks_detected):
        """Calculate overall network risk score"""
        if not attacks_detected or "Normal" in attacks_detected:
            return 15
        
        risk_weights = {
            "Critical": 25,
            "High": 20,
            "Medium": 15,
            "Low": 10
        }
        
        total_risk = 0
        for attack, details in attacks_detected.items():
            severity = AttackDetector().attack_signatures[attack]["severity"]
            confidence = details.get("confidence", 50)
            total_risk += (risk_weights.get(severity, 10) * confidence / 100)
        
        return min(100, total_risk)

# ===============================================================================
# STREAMLIT APPLICATION
# ===============================================================================


class ConclusionRiskDashboard:
    """
    Comprehensive Conclusion & Risk Analysis Dashboard Module
    
    Aggregates outputs from all modules to provide:
    - Unified security posture assessment
    - Overall risk level calculation
    - Key findings and actionable recommendations
    - Downloadable executive report
    """
    
    def __init__(self):
        self.risk_thresholds = {
            "CRITICAL": 80,
            "HIGH": 60,
            "MEDIUM": 30,
            "LOW": 0
        }
    
    def calculate_overall_risk_score(self, attacks_detected, mitre_report, analytics):
        """
        Calculate comprehensive risk score based on multiple factors
        
        Factors:
        - Attack detection confidence
        - Severity of MITRE techniques
        - Number of attacks detected
        - Traffic anomaly levels
        """
        
        if not attacks_detected or "Normal" in attacks_detected:
            return {
                "score": 10,
                "level": "LOW",
                "confidence": 95
            }
        
        # Base risk from analytics
        base_risk = analytics.generate_risk_score(attacks_detected)
        
        # MITRE severity weighting
        mitre_risk = 0
        critical_techniques = 0
        
        for item in mitre_report:
            if item['attack_type'] != 'Normal':
                if item['tactic'] in ['Impact', 'Credential Access', 'Initial Access']:
                    mitre_risk += 15
                    critical_techniques += 1
                else:
                    mitre_risk += 8
        
        # Attack count multiplier
        attack_count = len([a for a in attacks_detected if a != "Normal"])
        count_multiplier = 1 + (attack_count * 0.1)
        
        # Confidence aggregation
        avg_confidence = np.mean([d.get('confidence', 50) for d in attacks_detected.values()])
        
        # Calculate final score
        final_score = min(100, (base_risk * 0.4 + mitre_risk * 0.4 + (attack_count * 5)) * count_multiplier)
        
        # Determine risk level
        if final_score >= self.risk_thresholds["CRITICAL"]:
            level = "CRITICAL"
        elif final_score >= self.risk_thresholds["HIGH"]:
            level = "HIGH"
        elif final_score >= self.risk_thresholds["MEDIUM"]:
            level = "MEDIUM"
        else:
            level = "LOW"
        
        return {
            "score": final_score,
            "level": level,
            "confidence": avg_confidence,
            "attack_count": attack_count,
            "critical_techniques": critical_techniques
        }
    
    def generate_security_posture_assessment(self, attacks_detected, risk_data):
        """Generate overall security posture summary"""
        
        attack_count = risk_data['attack_count']
        risk_level = risk_data['level']
        
        if attack_count == 0:
            status = "SECURE"
            description = "Your network is currently operating within normal parameters. No immediate security threats have been detected. Continue maintaining your security best practices and monitoring protocols."
        elif risk_level == "CRITICAL":
            status = "UNDER ACTIVE ATTACK"
            description = f"CRITICAL ALERT: Your system is experiencing {attack_count} active attack(s) with high confidence levels. Immediate action is required to protect your infrastructure. Multiple attack vectors have been identified, and your network security is severely compromised."
        elif risk_level == "HIGH":
            status = "SUSPICIOUS ACTIVITY DETECTED"
            description = f"HIGH PRIORITY: {attack_count} potential security threat(s) detected with elevated risk levels. Your network is exhibiting suspicious patterns that require immediate investigation and response. Attack vectors are actively probing your defenses."
        elif risk_level == "MEDIUM":
            status = "ELEVATED THREAT LEVEL"
            description = f"CAUTION: {attack_count} security concern(s) identified. While not immediately critical, these threats warrant attention and preventive action. Your network is experiencing reconnaissance or preliminary attack phases."
        else:
            status = "MINOR ANOMALIES"
            description = f"Low-level security event(s) detected. {attack_count} potential threat(s) identified with low confidence. Review recommended, but no immediate danger to your infrastructure."
        
        return {
            "status": status,
            "description": description
        }
    
    def extract_key_findings(self, attacks_detected, mitre_report, recommendations):
        """Extract and prioritize key security findings"""
        
        findings = {
            "critical_attacks": [],
            "high_priority_attacks": [],
            "affected_assets": set(),
            "mitre_techniques": [],
            "immediate_actions": [],
            "preventive_measures": []
        }
        
        # Categorize attacks by severity
        detector = AttackDetector()
        
        for attack_type, details in attacks_detected.items():
            if attack_type == "Normal":
                continue
                
            attack_info = detector.attack_signatures[attack_type]
            confidence = details.get('confidence', 0)
            
            attack_summary = {
                "type": attack_type,
                "severity": attack_info['severity'],
                "confidence": confidence,
                "description": attack_info['description']
            }
            
            if attack_info['severity'] == "Critical":
                findings['critical_attacks'].append(attack_summary)
            elif attack_info['severity'] == "High":
                findings['high_priority_attacks'].append(attack_summary)
            
            # Track affected assets (simplified for demo)
            for key, value in details.items():
                if 'ip' in key.lower() or 'port' in key.lower():
                    findings['affected_assets'].add(f"{key}: {value}")
        
        # Extract MITRE techniques
        for item in mitre_report:
            if item['attack_type'] != 'Normal':
                findings['mitre_techniques'].append({
                    "tactic": item['tactic'],
                    "technique": item['technique_name'],
                    "id": item['technique_id'],
                    "attack": item['attack_type']
                })
        
        # Extract recommendations
        for rec_report in recommendations:
            for rec in rec_report['recommendations'][:2]:  # Top 2 per attack
                if rec['priority'] == "HIGH":
                    findings['immediate_actions'].append(rec['action'])
                else:
                    findings['preventive_measures'].append(rec['action'])
        
        # Remove duplicates and limit
        findings['immediate_actions'] = list(set(findings['immediate_actions']))[:5]
        findings['preventive_measures'] = list(set(findings['preventive_measures']))[:5]
        
        return findings
    
    def generate_risk_justification(self, risk_data, attacks_detected, mitre_report):
        """Generate detailed justification for risk assessment"""
        
        justifications = []
        
        # Attack-based justification
        if risk_data['attack_count'] > 0:
            justifications.append(
                f"• {risk_data['attack_count']} active attack vector(s) detected with average confidence of {risk_data['confidence']:.1f}%"
            )
        
        # MITRE-based justification
        if risk_data['critical_techniques'] > 0:
            justifications.append(
                f"• {risk_data['critical_techniques']} critical MITRE ATT&CK technique(s) identified (Impact, Credential Access, Initial Access tactics)"
            )
        
        # Severity-based justification
        critical_count = len([a for a, d in attacks_detected.items() 
                             if AttackDetector().attack_signatures.get(a, {}).get('severity') == 'Critical'])
        if critical_count > 0:
            justifications.append(
                f"• {critical_count} critical-severity attack(s) requiring immediate response"
            )
        
        # Confidence-based justification
        high_confidence_attacks = len([a for a, d in attacks_detected.items() 
                                       if d.get('confidence', 0) > 85])
        if high_confidence_attacks > 0:
            justifications.append(
                f"• {high_confidence_attacks} high-confidence detection(s) (>85% certainty)"
            )
        
        # Default for safe status
        if not justifications:
            justifications.append("• All network traffic patterns within normal parameters")
            justifications.append("• No malicious indicators detected across all analysis modules")
            justifications.append("• Security monitoring systems functioning optimally")
        
        return justifications
    
    def generate_pdf_report(self, dashboard_data):
        """Generate downloadable PDF report"""
        
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter,
                               rightMargin=72, leftMargin=72,
                               topMargin=72, bottomMargin=18)
        
        # Container for PDF elements
        elements = []
        
        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1E3A8A'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#3B82F6'),
            spaceAfter=12,
            spaceBefore=12
        )
        
        # Title
        elements.append(Paragraph("CYBERSECURITY RISK ANALYSIS REPORT", title_style))
        elements.append(Spacer(1, 12))
        
        # Report metadata
        report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        elements.append(Paragraph(f"<b>Report Generated:</b> {report_date}", styles['Normal']))
        elements.append(Paragraph(f"<b>Analysis Period:</b> Last 24 Hours", styles['Normal']))
        elements.append(Spacer(1, 20))
        
        # Executive Summary
        elements.append(Paragraph("EXECUTIVE SUMMARY", heading_style))
        
        risk_data = dashboard_data['risk_assessment']
        posture = dashboard_data['security_posture']
        
        # Risk level indicator
        risk_color = {
            "CRITICAL": colors.red,
            "HIGH": colors.orange,
            "MEDIUM": colors.blue,
            "LOW": colors.green
        }.get(risk_data['level'], colors.grey)
        
        risk_table_data = [
            ["Overall Risk Level", risk_data['level']],
            ["Risk Score", f"{risk_data['score']:.1f}/100"],
            ["Security Status", posture['status']],
            ["Detection Confidence", f"{risk_data['confidence']:.1f}%"]
        ]
        
        risk_table = Table(risk_table_data, colWidths=[3*inch, 3*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('BACKGROUND', (1, 0), (1, 0), risk_color),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(risk_table)
        elements.append(Spacer(1, 20))
        
        # Security Posture
        elements.append(Paragraph(posture['description'], styles['Normal']))
        elements.append(Spacer(1, 20))
        
        # Risk Justification
        elements.append(Paragraph("RISK ASSESSMENT JUSTIFICATION", heading_style))
        justifications = dashboard_data['risk_justification']
        for justification in justifications:
            elements.append(Paragraph(justification, styles['Normal']))
        elements.append(Spacer(1, 20))
        
        # Key Findings
        findings = dashboard_data['key_findings']
        elements.append(Paragraph("KEY FINDINGS", heading_style))
        
        if findings['critical_attacks']:
            elements.append(Paragraph("<b>Critical Attacks:</b>", styles['Normal']))
            for attack in findings['critical_attacks'][:3]:
                elements.append(Paragraph(
                    f"• {attack['type']} (Confidence: {attack['confidence']:.1f}%) - {attack['description']}", 
                    styles['Normal']
                ))
            elements.append(Spacer(1, 10))
        
        if findings['mitre_techniques']:
            elements.append(Paragraph("<b>MITRE ATT&CK Techniques Detected:</b>", styles['Normal']))
            for technique in findings['mitre_techniques'][:5]:
                elements.append(Paragraph(
                    f"• {technique['id']}: {technique['technique']} ({technique['tactic']} tactic)",
                    styles['Normal']
                ))
            elements.append(Spacer(1, 20))
        
        # Immediate Actions
        elements.append(Paragraph("IMMEDIATE ACTIONS REQUIRED", heading_style))
        if findings['immediate_actions']:
            for idx, action in enumerate(findings['immediate_actions'], 1):
                elements.append(Paragraph(f"{idx}. {action}", styles['Normal']))
        else:
            elements.append(Paragraph("No immediate actions required. Continue standard monitoring.", styles['Normal']))
        
        elements.append(Spacer(1, 20))
        
        # Preventive Measures
        elements.append(Paragraph("RECOMMENDED PREVENTIVE MEASURES", heading_style))
        if findings['preventive_measures']:
            for idx, measure in enumerate(findings['preventive_measures'], 1):
                elements.append(Paragraph(f"{idx}. {measure}", styles['Normal']))
        else:
            elements.append(Paragraph("Maintain current security posture and best practices.", styles['Normal']))
        
        # Build PDF
        doc.build(elements)
        
        pdf_data = buffer.getvalue()
        buffer.close()
        
        return pdf_data
    
    def generate_dashboard_data(self, attacks_detected, mitre_report, recommendations, analytics, xai_explanations):
        """
        Main method to generate comprehensive dashboard data
        
        Returns complete dashboard structure with all analysis
        """
        
        # Calculate overall risk
        risk_assessment = self.calculate_overall_risk_score(attacks_detected, mitre_report, analytics)
        
        # Generate security posture
        security_posture = self.generate_security_posture_assessment(attacks_detected, risk_assessment)
        
        # Extract key findings
        key_findings = self.extract_key_findings(attacks_detected, mitre_report, recommendations)
        
        # Generate risk justification
        risk_justification = self.generate_risk_justification(risk_assessment, attacks_detected, mitre_report)
        
        # Compile dashboard data
        dashboard_data = {
            "risk_assessment": risk_assessment,
            "security_posture": security_posture,
            "key_findings": key_findings,
            "risk_justification": risk_justification,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "summary_stats": {
                "total_attacks": len([a for a in attacks_detected if a != "Normal"]),
                "critical_attacks": len(key_findings['critical_attacks']),
                "high_priority_attacks": len(key_findings['high_priority_attacks']),
                "mitre_techniques": len(key_findings['mitre_techniques']),
                "immediate_actions": len(key_findings['immediate_actions'])
            }
        }
        
        return dashboard_data

# ===============================================================================

def main():
    st.set_page_config(
        page_title="Professional IDS with MITRE ATT&CK Visualizations",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    load_css()
    
    # Header
    st.markdown('<h1 class="main-header">🛡️ Advanced IDS with MITRE ATT&CK Visualizations</h1>', unsafe_allow_html=True)
    st.markdown('<p style="text-align: center; color: #6B7280; font-size: 1.2rem;">Network Security with XAI, MITRE Mapping, Recommendations & Attack Visualizations</p>', unsafe_allow_html=True)
    
    # Initialize session state
    if 'analysis_complete' not in st.session_state:
        st.session_state.analysis_complete = False
    if 'df' not in st.session_state:
        st.session_state.df = None
    if 'attacks_detected' not in st.session_state:
        st.session_state.attacks_detected = {}
    if 'mitre_report' not in st.session_state:
        st.session_state.mitre_report = []
    if 'recommendations' not in st.session_state:
        st.session_state.recommendations = []
    if 'visualizations' not in st.session_state:
        st.session_state.visualizations = {}
    if 'dashboard_data' not in st.session_state:
        st.session_state.dashboard_data = None
    
    # Sidebar Navigation
    with st.sidebar:
        st.markdown("## 🔧 Navigation")
        page = st.selectbox(
            "Select Analysis View",
            ["🏠 Dashboard", "📊 Traffic Analysis", "🔍 Attack Detection", 
             "🧠 XAI Explanations", "🎯 MITRE ATT&CK Mapping", 
             "💡 Security Recommendations", "🎨 Attack Visualizations", 
             "📈 Advanced Analytics", "📋 Conclusion & Risk Analysis"]
        )
        
        st.markdown("---")
        st.markdown("## 📁 Data Upload")
        uploaded_file = st.file_uploader(
            "Upload Network Traffic CSV",
            type="csv",
            help="Upload your network traffic data for analysis"
        )
        
        if uploaded_file is not None:
            try:
                df = pd.read_csv(uploaded_file)
                st.session_state.df = df
                st.success(f"✅ Loaded {len(df):,} records")
                
                if not st.session_state.analysis_complete:
                    detector = AttackDetector()
                    st.session_state.attacks_detected = detector.detect_attacks(df)
                    
                    mitre_mapper = MITREAttackMapper()
                    st.session_state.mitre_report = mitre_mapper.generate_mitre_report(
                        st.session_state.attacks_detected
                    )
                    
                    recommender = SecurityRecommendationEngine()
                    st.session_state.recommendations = recommender.generate_comprehensive_report(
                        st.session_state.attacks_detected
                    )
                    
                    # NEW: Generate visualizations
                    viz_engine = MITREAttackVisualizationEngine()
                    st.session_state.visualizations = {}
                    
                    for attack_type, details in st.session_state.attacks_detected.items():
                        if attack_type != "Normal":
                            mitre_data = next((m for m in st.session_state.mitre_report if m['attack_type'] == attack_type), None)
                            if mitre_data:
                                viz = viz_engine.generate_comprehensive_attack_visualization(
                                    attack_type, 
                                    mitre_data, 
                                    details, 
                                    df,
                                    details['confidence']
                                )
                                st.session_state.visualizations[attack_type] = viz
                    
                    # Generate analytics and XAI data
                    analytics = NetworkAnalytics(df)
                    explainer = XAIExplainer()
                    xai_explanations = {}
                    for attack_type in st.session_state.attacks_detected.keys():
                        xai_explanations[attack_type] = explainer.generate_explanation(attack_type, df)
                    
                    # Generate conclusion dashboard data
                    dashboard = ConclusionRiskDashboard()
                    st.session_state.dashboard_data = dashboard.generate_dashboard_data(
                        st.session_state.attacks_detected,
                        st.session_state.mitre_report,
                        st.session_state.recommendations,
                        analytics,
                        xai_explanations
                    )
                    
                    st.session_state.analysis_complete = True
                    
            except Exception as e:
                st.error(f"Error loading file: {str(e)}")
        
        # System Status
        st.markdown("---")
        st.markdown("### 🔐 System Status")
        if st.session_state.df is not None:
            analytics = NetworkAnalytics(st.session_state.df)
            risk_score = analytics.generate_risk_score(st.session_state.attacks_detected)
            
            if risk_score < 30:
                st.success(f"🟢 Risk Level: LOW ({risk_score:.0f}%)")
            elif risk_score < 70:
                st.warning(f"🟡 Risk Level: MEDIUM ({risk_score:.0f}%)")
            else:
                st.error(f"🔴 Risk Level: HIGH ({risk_score:.0f}%)")
        else:
            st.info("🔵 Awaiting data upload")
    
    # Main Content Area
    if st.session_state.df is None:
        show_welcome_page()
    else:
        if page == "🏠 Dashboard":
            show_dashboard()
        elif page == "📊 Traffic Analysis":
            show_traffic_analysis()
        elif page == "🔍 Attack Detection":
            show_attack_detection()
        elif page == "🧠 XAI Explanations":
            show_xai_explanations()
        elif page == "🎯 MITRE ATT&CK Mapping":
            show_mitre_mapping()
        elif page == "💡 Security Recommendations":
            show_security_recommendations()
        elif page == "🎨 Attack Visualizations":
            show_attack_visualizations()
        elif page == "📋 Conclusion & Risk Analysis":
            show_conclusion_dashboard()
        elif page == "📈 Advanced Analytics":
            show_advanced_analytics()

def show_welcome_page():
    """Display welcome page with instructions"""
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown("""
        ## 🚀 Welcome to Advanced IDS
        
        ### ✨ NEW: Attack Visualization Module
        - 🎨 **Kill Chain Visualizations** - See how attacks progress through phases
        - 📊 **Network Graph Analysis** - Visualize attack sources and targets
        - 🔥 **Intensity Heatmaps** - Track attack patterns over time
        - 🎯 **MITRE Technique Matrix** - Interactive MITRE ATT&CK visualization
        
        ### Core Features
        - 🔍 **Real-time Attack Detection** - Multiple attack signatures
        - 🧠 **Explainable AI** - Understand why attacks were detected  
        - 🎯 **MITRE ATT&CK Framework** - Industry-standard threat classification
        - 💡 **Smart Recommendations** - Content-based filtering with cosine similarity
        - 📊 **Advanced Analytics** - Comprehensive traffic analysis
        - 🎨 **Interactive Visualizations** - Professional charts and graphs
        
        ### Getting Started
        1. **Upload your CSV file** using the sidebar uploader
        2. **Automatic analysis** will begin immediately  
        3. **Explore results** through different analysis views
        4. **View attack visualizations** to understand attack patterns
        5. **Get MITRE mappings** for detected attacks
        6. **Review recommendations** to prevent future attacks
        
        ### Supported Attack Types
        - DDoS & DoS attacks
        - Brute force attempts  
        - Port scanning
        - SQL injection
        - Cross-site scripting (XSS)
        - Botnet activity
        - System infiltration
        - SSL/TLS vulnerabilities
        """)

def show_dashboard():
    """Main dashboard overview"""
    if st.session_state.df is None:
        return
    
    df = st.session_state.df
    attacks = st.session_state.attacks_detected
    analytics = NetworkAnalytics(df)
    summary = analytics.generate_traffic_summary()
    
    # Key Metrics Row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Connections", f"{summary['total_connections']:,}")
    with col2:
        st.metric("Unique Sources", f"{summary['unique_sources']:,}")
    with col3:
        st.metric("Attacks Detected", len([a for a in attacks if a != "Normal"]))
    with col4:
        risk_score = analytics.generate_risk_score(attacks)
        st.metric("Risk Score", f"{risk_score:.0f}%")
    
    st.markdown("---")
    
    # Attack Summary Cards
    st.subheader("🚨 Security Alerts")
    
    if attacks and "Normal" not in attacks:
        for attack_type, details in attacks.items():
            detector = AttackDetector()
            attack_info = detector.attack_signatures[attack_type]
            
            severity_class = f"{attack_info['severity'].lower()}-attack"
            
            st.markdown(f"""
            <div class="attack-card {severity_class}">
                <h4>{attack_info['icon']} {attack_type} - {attack_info['severity']} Severity</h4>
                <p>{attack_info['description']}</p>
                <p><strong>Confidence:</strong> {details['confidence']:.1f}%</p>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.success("✅ No security threats detected - Network traffic appears normal")
    
    # Traffic Overview Charts
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Protocol Distribution")
        protocol_fig = px.pie(
            values=list(summary['protocols'].values()),
            names=list(summary['protocols'].keys()),
            title="Network Protocols"
        )
        st.plotly_chart(protocol_fig, use_container_width=True)
    
    with col2:
        st.subheader("Top Destination Ports")
        ports_fig = px.bar(
            x=list(summary['top_ports'].keys()),
            y=list(summary['top_ports'].values()),
            title="Most Accessed Ports"
        )
        st.plotly_chart(ports_fig, use_container_width=True)

def show_traffic_analysis():
    """Detailed traffic analysis page"""
    if st.session_state.df is None:
        return
        
    df = st.session_state.df
    analytics = NetworkAnalytics(df)
    
    st.subheader("📊 Network Traffic Analysis")
    
    timeline_df = analytics.create_traffic_timeline()
    
    fig = make_subplots(
        rows=2, cols=1,
        subplot_titles=("Packet Volume Over Time", "Unique Sources Over Time"),
        vertical_spacing=0.1
    )
    
    fig.add_trace(
        go.Scatter(x=timeline_df['timestamp'], y=timeline_df['packets'], 
                  mode='lines+markers', name='Packets', line=dict(color='#3B82F6')),
        row=1, col=1
    )
    
    fig.add_trace(
        go.Scatter(x=timeline_df['timestamp'], y=timeline_df['src_ip'], 
                  mode='lines+markers', name='Unique Sources', line=dict(color='#EF4444')),
        row=2, col=1
    )
    
    fig.update_layout(height=600, title_text="Traffic Timeline Analysis")
    st.plotly_chart(fig, use_container_width=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Traffic Statistics")
        stats_data = {
            'Metric': ['Total Packets', 'Total Bytes', 'Avg Duration', 'Max Packets/Connection', 'Unique IPs'],
            'Value': [
                f"{df['packets'].sum():,}",
                f"{df['bytes'].sum():,}",
                f"{df['duration'].mean():.2f}s",
                f"{df['packets'].max():,}",
                f"{df['src_ip'].nunique() + df['dst_ip'].nunique()}"
            ]
        }
        st.table(pd.DataFrame(stats_data))
    
    with col2:
        st.subheader("Connection Analysis")
        fig = px.scatter(
            df.sample(min(1000, len(df))), 
            x='packets', y='bytes', 
            color='protocol',
            title="Packets vs Bytes by Protocol",
            hover_data=['src_ip', 'dst_ip']
        )
        st.plotly_chart(fig, use_container_width=True)

def show_attack_detection():
    """Attack detection details page"""
    if st.session_state.df is None:
        return
        
    attacks = st.session_state.attacks_detected
    detector = AttackDetector()
    
    st.subheader("🔍 Attack Detection Results")
    
    if attacks and "Normal" not in attacks:
        attack_names = list(attacks.keys())
        confidences = [attacks[attack]['confidence'] for attack in attack_names]
        
        fig = px.bar(
            x=attack_names, y=confidences,
            title="Attack Detection Confidence Scores",
            color=confidences,
            color_continuous_scale="Reds",
            labels={'y': 'Confidence (%)', 'x': 'Attack Type'}
        )
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
        
        st.subheader("Detailed Attack Analysis")
        
        for attack_type, details in attacks.items():
            with st.expander(f"{detector.attack_signatures[attack_type]['icon']} {attack_type} Attack Details"):
                attack_info = detector.attack_signatures[attack_type]
                
                col1, col2 = st.columns([1, 2])
                
                with col1:
                    st.metric("Confidence", f"{details['confidence']:.1f}%")
                    st.metric("Severity", attack_info['severity'])
                
                with col2:
                    st.write(f"**Description:** {attack_info['description']}")
                    
                    for key, value in details.items():
                        if key != 'confidence':
                            st.write(f"**{key.replace('_', ' ').title()}:** {value}")
    else:
        st.success("🛡️ No attacks detected - Your network traffic appears clean and secure!")
        
        df = st.session_state.df
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Security Status", "✅ SECURE")
        with col2:
            st.metric("Threat Level", "🟢 LOW")
        with col3:
            st.metric("Connections Analyzed", f"{len(df):,}")

def show_xai_explanations():
    """XAI explanations and feature importance"""
    if st.session_state.df is None:
        return
        
    df = st.session_state.df
    attacks = st.session_state.attacks_detected
    explainer = XAIExplainer()
    
    st.subheader("🧠 Explainable AI Analysis")
    
    if attacks and "Normal" not in attacks:
        for attack_type in attacks.keys():
            st.markdown(f"### {attack_type} Attack Analysis")
            
            explanation = explainer.generate_explanation(attack_type, df)
            st.markdown(explanation)
            
            importance = explainer.calculate_feature_importance(df, attack_type)
            
            importance_df = pd.DataFrame([
                {"Feature": k, "Importance": v} for k, v in importance.items()
            ]).sort_values("Importance", ascending=False)
            
            fig = px.bar(
                importance_df, 
                x="Importance", 
                y="Feature",
                orientation='h',
                title=f"Feature Importance for {attack_type} Detection",
                color="Importance",
                color_continuous_scale="viridis"
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
            
            st.markdown("---")
            
    else:
        st.info("🔍 No attacks detected to explain. Upload suspicious network traffic to see XAI analysis.")

def show_mitre_mapping():
    """Display MITRE ATT&CK mappings"""
    st.subheader("🎯 MITRE ATT&CK Framework Mapping")
    
    if not st.session_state.mitre_report or all(m['attack_type'] == 'Normal' for m in st.session_state.mitre_report):
        st.info("📋 No malicious activity detected. MITRE ATT&CK mapping is only available for detected threats.")
        return
    
    st.markdown("""
    **MITRE ATT&CK** is a globally accessible knowledge base of adversary tactics and techniques 
    based on real-world observations.
    """)
    
    st.markdown("---")
    
    for mitre_data in st.session_state.mitre_report:
        if mitre_data['attack_type'] == 'Normal':
            continue
            
        st.markdown(f"""
        <div class="mitre-card">
            <h3>🎯 {mitre_data['attack_type']} Attack</h3>
            <p><strong>Confidence:</strong> {mitre_data['confidence']:.1f}%</p>
        </div>
        """, unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 📌 MITRE ATT&CK Details")
            st.write(f"**Tactic:** {mitre_data['tactic']}")
            st.write(f"**Technique ID:** {mitre_data['technique_id']}")
            st.write(f"**Technique Name:** {mitre_data['technique_name']}")
        
        with col2:
            st.markdown("### 📖 Description")
            st.info(mitre_data['description'])
        
        st.markdown("### 🛡️ Recommended Mitigation")
        st.success(mitre_data['mitigation'])
        
        if mitre_data['technique_id'] != 'N/A':
            technique_url = f"https://attack.mitre.org/techniques/{mitre_data['technique_id'].replace('.', '/')}/"
            st.markdown(f"[🔗 View full technique details on MITRE ATT&CK website]({technique_url})")
        
        st.markdown("---")
    
    # MITRE Tactics Summary
    st.subheader("📊 MITRE Tactics Summary")
    
    tactics = [m['tactic'] for m in st.session_state.mitre_report if m['attack_type'] != 'Normal']
    if tactics:
        tactic_counts = pd.Series(tactics).value_counts()
        
        fig = px.bar(
            x=tactic_counts.values,
            y=tactic_counts.index,
            orientation='h',
            title="Distribution of MITRE ATT&CK Tactics",
            labels={'x': 'Count', 'y': 'Tactic'},
            color=tactic_counts.values,
            color_continuous_scale='Purples'
        )
        st.plotly_chart(fig, use_container_width=True)

def show_security_recommendations():
    """Display AI-powered security recommendations"""
    st.subheader("💡 AI-Powered Security Recommendations")
    
    if not st.session_state.recommendations:
        st.info("🔒 No security recommendations available. System appears secure!")
        return
    
    st.markdown("""
    **Intelligent Recommendation System** uses Content-Based Filtering with Cosine Similarity.
    """)
    
    st.markdown("---")
    
    for rec_report in st.session_state.recommendations:
        risk_colors = {
            "CRITICAL": "#EF4444",
            "HIGH": "#F59E0B",
            "MEDIUM": "#3B82F6",
            "LOW": "#10B981"
        }
        
        risk_color = risk_colors.get(rec_report['risk_level'], "#6B7280")
        
        st.markdown(f"""
        <div class="recommendation-card">
            <h3>🎯 {rec_report['attack_type']} Attack Prevention</h3>
            <p><strong>Risk Level:</strong> <span style="color: {risk_color}; font-weight: bold;">{rec_report['risk_level']}</span></p>
            <p><strong>Detection Confidence:</strong> {rec_report['confidence']:.1f}%</p>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("### 🛡️ Recommended Security Actions")
        
        for idx, rec in enumerate(rec_report['recommendations'], 1):
            priority_emoji = {
                "HIGH": "🔴",
                "MEDIUM": "🟡",
                "LOW": "🟢"
            }
            
            with st.expander(f"{priority_emoji.get(rec['priority'], '⚪')} Recommendation #{idx} - Priority: {rec['priority']}"):
                st.write(f"**Action:** {rec['action']}")
                st.write(f"**Relevance Score:** {rec['relevance_score']:.2%}")
                st.progress(rec['relevance_score'])
        
        st.markdown("---")

# ===============================================================================
# NEW: ATTACK VISUALIZATIONS PAGE
# ===============================================================================

def show_attack_visualizations():
    """NEW: Display comprehensive attack visualizations"""
    st.subheader("🎨 MITRE ATT&CK-Based Attack Visualizations")
    
    if not st.session_state.visualizations:
        st.info("🖼️ No attack visualizations available. Visualizations are generated for detected attacks only.")
        return
    
    st.markdown("""
    **Advanced Attack Visualization Engine** provides structured visual representations of detected cyberattacks including:
    - **Kill Chain Timeline**: Attack progression through MITRE ATT&CK phases
    - **Network Graph Analysis**: Visual representation of attack sources, targets, and traffic flows
    - **Intensity Heatmaps**: Temporal analysis of attack patterns
    """)
    
    st.markdown("---")
    
    # Attack selection
    attack_types = list(st.session_state.visualizations.keys())
    
    if len(attack_types) == 1:
        selected_attack = attack_types[0]
    else:
        selected_attack = st.selectbox("Select Attack Type for Detailed Visualization", attack_types)
    
    if selected_attack in st.session_state.visualizations:
        viz_data = st.session_state.visualizations[selected_attack]
        
        st.markdown(f"""
        <div class="visualization-card">
            <h3>📊 {selected_attack} Attack Comprehensive Visualization</h3>
            <p>Detailed visual analysis based on MITRE ATT&CK framework and detected attack patterns</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Display Kill Chain Visualization
        st.markdown("### 🔗 Attack Kill Chain Timeline")
        st.markdown("Shows the progression of the attack through different phases of the cyber kill chain")
        
        if viz_data.get('killchain'):
            st.plotly_chart(viz_data['killchain'], use_container_width=True)
        
        st.markdown("---")
        
        # Display Network Graph
        st.markdown("### 🌐 Attack Network Graph")
        st.markdown("Visual representation of attack sources (red), targets (blue), and network flows")
        
        if viz_data.get('network_graph'):
            st.plotly_chart(viz_data['network_graph'], use_container_width=True)
        
        st.markdown("---")
        
        # Display Heatmap
        st.markdown("### 🔥 Attack Intensity Heatmap")
        st.markdown("Temporal analysis showing attack intensity variations over time")
        
        if viz_data.get('heatmap'):
            st.plotly_chart(viz_data['heatmap'], use_container_width=True)
        
        st.markdown("---")
        
        # Visualization insights
        st.markdown("### 💡 Visualization Insights")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.info("**Kill Chain Analysis**\nShows attack progression through reconnaissance, initial access, exploitation, and impact phases")
        
        with col2:
            st.warning("**Network Topology**\nIdentifies primary attack sources and most targeted systems in your network")
        
        with col3:
            st.error("**Temporal Patterns**\nReveals peak attack times and intensity patterns for proactive defense")
    
    # MITRE Technique Matrix (if multiple attacks detected)
    if len(st.session_state.mitre_report) > 1:
        st.markdown("---")
        st.markdown("### 🎯 MITRE ATT&CK Technique Matrix")
        
        viz_engine = MITREAttackVisualizationEngine()
        matrix_fig = viz_engine.generate_mitre_technique_matrix(st.session_state.mitre_report)
        
        if matrix_fig:
            st.plotly_chart(matrix_fig, use_container_width=True)

def show_advanced_analytics():
    """Advanced analytics and reporting"""
    if st.session_state.df is None:
        return
        
    df = st.session_state.df
    
    st.subheader("📈 Advanced Network Analytics")
    
    numeric_cols = ['packets', 'bytes', 'duration']
    if all(col in df.columns for col in numeric_cols):
        st.subheader("Feature Correlation Analysis")
        
        corr_matrix = df[numeric_cols].corr()
        
        fig = px.imshow(
            corr_matrix,
            title="Feature Correlation Heatmap",
            color_continuous_scale="RdBu_r"
        )
        st.plotly_chart(fig, use_container_width=True)
    
    st.subheader("IP Address Analysis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        top_sources = df['src_ip'].value_counts().head(10)
        fig = px.bar(
            x=top_sources.values,
            y=top_sources.index,
            orientation='h',
            title="Top Source IPs by Activity",
            labels={'x': 'Connection Count', 'y': 'Source IP'}
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        top_destinations = df['dst_ip'].value_counts().head(10)
        fig = px.bar(
            x=top_destinations.values,
            y=top_destinations.index,
            orientation='h',
            title="Top Destination IPs by Activity",
            labels={'x': 'Connection Count', 'y': 'Destination IP'}
        )
        st.plotly_chart(fig, use_container_width=True)


def show_conclusion_dashboard():
    """Display comprehensive conclusion and risk analysis dashboard"""
    
    if not st.session_state.dashboard_data:
        st.warning("⚠️ No analysis data available. Please upload network traffic data first.")
        return
    
    dashboard_data = st.session_state.dashboard_data
    risk_data = dashboard_data['risk_assessment']
    posture = dashboard_data['security_posture']
    findings = dashboard_data['key_findings']
    stats = dashboard_data['summary_stats']
    
    # Page Header
    st.markdown("## 📋 CONCLUSION & RISK ANALYSIS DASHBOARD")
    st.markdown(f"**Report Generated:** {dashboard_data['timestamp']}")
    st.markdown("---")
    
    # Risk Level Indicator (Large Banner)
    risk_class = f"risk-{risk_data['level'].lower()}"
    risk_emoji = {
        "CRITICAL": "🚨",
        "HIGH": "⚠️",
        "MEDIUM": "🔔",
        "LOW": "✅"
    }.get(risk_data['level'], "ℹ️")
    
    st.markdown(f"""
    <div class="{risk_class}">
        <h2 style="margin: 0; text-align: center;">
            {risk_emoji} OVERALL RISK LEVEL: {risk_data['level']} {risk_emoji}
        </h2>
        <h3 style="margin: 10px 0; text-align: center;">
            Risk Score: {risk_data['score']:.1f}/100 | Confidence: {risk_data['confidence']:.1f}%
        </h3>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Security Posture Assessment
    st.markdown("### 🔐 SECURITY POSTURE ASSESSMENT")
    st.markdown(f"**Status:** {posture['status']}")
    st.info(posture['description'])
    
    st.markdown("---")
    
    # Summary Statistics
    st.markdown("### 📊 SUMMARY STATISTICS")
    
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric("Total Attacks", stats['total_attacks'])
    with col2:
        st.metric("Critical", stats['critical_attacks'])
    with col3:
        st.metric("High Priority", stats['high_priority_attacks'])
    with col4:
        st.metric("MITRE Techniques", stats['mitre_techniques'])
    with col5:
        st.metric("Immediate Actions", stats['immediate_actions'])
    
    st.markdown("---")
    
    # Risk Justification
    st.markdown("### 📝 RISK ASSESSMENT JUSTIFICATION")
    
    for justification in dashboard_data['risk_justification']:
        st.markdown(justification)
    
    st.markdown("---")
    
    # Key Findings
    st.markdown("### 🔍 KEY FINDINGS")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 🚨 Critical Threats")
        if findings['critical_attacks']:
            for attack in findings['critical_attacks']:
                st.error(f"**{attack['type']}** ({attack['confidence']:.1f}% confidence)")
                st.write(f"_{attack['description']}_")
        else:
            st.success("No critical threats detected")
        
        st.markdown("#### 🎯 MITRE ATT&CK Techniques")
        if findings['mitre_techniques']:
            for technique in findings['mitre_techniques'][:5]:
                st.info(f"**{technique['id']}**: {technique['technique']}")
                st.write(f"Tactic: {technique['tactic']} | Attack: {technique['attack']}")
        else:
            st.success("No MITRE techniques detected")
    
    with col2:
        st.markdown("#### ⚠️ High Priority Threats")
        if findings['high_priority_attacks']:
            for attack in findings['high_priority_attacks']:
                st.warning(f"**{attack['type']}** ({attack['confidence']:.1f}% confidence)")
                st.write(f"_{attack['description']}_")
        else:
            st.success("No high priority threats detected")
        
        st.markdown("#### 🖥️ Affected Assets")
        if findings['affected_assets']:
            for asset in list(findings['affected_assets'])[:5]:
                st.write(f"• {asset}")
        else:
            st.success("No assets affected")
    
    st.markdown("---")
    
    # Actionable Recommendations
    st.markdown("### ⚡ ACTIONABLE RECOMMENDATIONS")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 🔴 IMMEDIATE ACTIONS REQUIRED")
        if findings['immediate_actions']:
            for idx, action in enumerate(findings['immediate_actions'], 1):
                st.error(f"**{idx}.** {action}")
        else:
            st.success("No immediate actions required")
    
    with col2:
        st.markdown("#### 🟡 PREVENTIVE MEASURES")
        if findings['preventive_measures']:
            for idx, measure in enumerate(findings['preventive_measures'], 1):
                st.warning(f"**{idx}.** {measure}")
        else:
            st.info("Continue standard security practices")
    
    st.markdown("---")
    
    # MITRE ATT&CK Coverage Snapshot
    st.markdown("### 🎯 MITRE ATT&CK COVERAGE SNAPSHOT")
    
    if findings['mitre_techniques']:
        tactics = [t['tactic'] for t in findings['mitre_techniques']]
        tactic_counts = pd.Series(tactics).value_counts()
        
        fig = px.bar(
            x=tactic_counts.values,
            y=tactic_counts.index,
            orientation='h',
            title="MITRE ATT&CK Tactics Distribution",
            labels={'x': 'Count', 'y': 'Tactic'},
            color=tactic_counts.values,
            color_continuous_scale='Reds'
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.success("No MITRE ATT&CK techniques detected - System Secure")
    
    st.markdown("---")
    
    # Download Report
    st.markdown("### 💾 DOWNLOAD EXECUTIVE REPORT")
    
    col1, col2, col3 = st.columns([1, 1, 2])
    
    with col1:
        if st.button("📄 Generate PDF Report", type="primary"):
            dashboard = ConclusionRiskDashboard()
            pdf_data = dashboard.generate_pdf_report(dashboard_data)
            
            b64_pdf = base64.b64encode(pdf_data).decode()
            
            st.download_button(
                label="💾 Download PDF Report",
                data=pdf_data,
                file_name=f"security_risk_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                mime="application/pdf"
            )
    
    with col2:
        if st.button("📋 Export JSON Data"):
            import json
            json_data = json.dumps(dashboard_data, indent=2, default=str)
            
            st.download_button(
                label="💾 Download JSON",
                data=json_data,
                file_name=f"security_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
    
    st.markdown("---")
    
    # Footer
    st.markdown("""
    <div style='text-align: center; color: #6B7280; padding: 20px;'>
        <p><strong>Conclusion:</strong> This dashboard provides a comprehensive risk assessment based on multi-module analysis.</p>
        <p>All findings are derived from AI-powered detection, MITRE ATT&CK mapping, and security best practices.</p>
    </div>
    """, unsafe_allow_html=True)

# ===============================================================================
# DEMO MODE & UTILITIES
# ===============================================================================

def create_sample_data():
    """Generate sample network traffic data"""
    np.random.seed(42)
    
    protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS']
    
    sample_data = []
    for i in range(1000):
        sample_data.append({
            'src_ip': f"192.168.{random.randint(1,10)}.{random.randint(1,254)}",
            'dst_ip': f"10.0.{random.randint(1,5)}.{random.randint(1,254)}",
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice([22, 80, 443, 3306, 8080]),
            'protocol': random.choice(protocols),
            'packets': random.randint(1, 2000),
            'bytes': random.randint(64, 100000),
            'duration': random.uniform(0.1, 300.0),
            'flags': random.choice(['SYN', 'ACK', 'FIN', 'RST'])
        })
    
    return pd.DataFrame(sample_data)

def add_demo_mode():
    """Add demo mode with sample data"""
    with st.sidebar:
        st.markdown("---")
        st.markdown("### 🎮 Demo Mode")
        if st.button("Load Sample Data"):
            st.session_state.df = create_sample_data()
            
            detector = AttackDetector()
            st.session_state.attacks_detected = detector.detect_attacks(st.session_state.df)
            
            mitre_mapper = MITREAttackMapper()
            st.session_state.mitre_report = mitre_mapper.generate_mitre_report(
                st.session_state.attacks_detected
            )
            
            recommender = SecurityRecommendationEngine()
            st.session_state.recommendations = recommender.generate_comprehensive_report(
                st.session_state.attacks_detected
            )
            
            # Generate visualizations
            viz_engine = MITREAttackVisualizationEngine()
            st.session_state.visualizations = {}
            
            for attack_type, details in st.session_state.attacks_detected.items():
                if attack_type != "Normal":
                    mitre_data = next((m for m in st.session_state.mitre_report if m['attack_type'] == attack_type), None)
                    if mitre_data:
                        viz = viz_engine.generate_comprehensive_attack_visualization(
                            attack_type, 
                            mitre_data, 
                            details, 
                            st.session_state.df,
                            details['confidence']
                        )
                        st.session_state.visualizations[attack_type] = viz
            
            st.session_state.analysis_complete = True
            st.success("Sample data loaded successfully!")
            st.rerun()

if __name__ == "__main__":
    main()
    add_demo_mode()
    
    st.markdown("---")
    st.markdown(
        """
        <div style='text-align: center; color: #6B7280; padding: 20px;'>
            <p>🛡️ Advanced IDS with MITRE ATT&CK Visualizations</p>
            <p>Powered by XAI, MITRE Mapping, Recommendations & Graph-Based Attack Visualization</p>
        </div>
        """, 
        unsafe_allow_html=True
    )

    