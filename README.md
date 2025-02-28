# Langgraph-Based-Agentic-Cybersecurity

# Security Agent

An AI-powered security automation framework that orchestrates security scanning tasks using LLMs and common security tools.

## Overview

The Security Agent uses LangGraph to create a workflow-based architecture that automates security scanning. It integrates with tools like nmap, gobuster, ffuf, and sqlmap, and uses LLMs (Llama3 via Groq) to plan tasks, analyze results, and generate comprehensive security reports.

## Features

- **Automated Task Planning**: Converts high-level security requests into specific executable tasks
- **Intelligent Analysis**: Examines scan results to identify additional security checks
- **Scope Management**: Ensures all scanning stays within authorized targets
- **Adaptive Retry Logic**: Automatically adjusts parameters and retries failed scans
- **Comprehensive Reporting**: Generates detailed findings with severity ratings and remediation recommendations

## Requirements

- Python 3.8+
- LangChain
- LangGraph
- Pydantic
- Groq API key (for LLM access)

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/security-agent.git
cd security-agent

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
cp .env.example .env
# Edit .env with your API keys
```

## Usage

```python
from security_agent import run_cybersecurity_agent, ScopeConfig

# Define authorized targets
scope = ScopeConfig(
    domains=["example.com", "*.example.com"],
    ip_ranges=["192.168.1.0/24"]
)

# Run a security assessment
result = run_cybersecurity_agent(
    "Scan example.com for open ports, directory enumeration, and SQL injection vulnerabilities",
    scope
)

# Display results
print(json.dumps(result.final_report, indent=2))
```

## System Design

The agent uses a state machine with the following workflow:

1. **Initialize Tasks**: Convert high-level request to specific tasks
2. **Execute Task**: Run the current security scan
3. **Analyze Results**: Examine outputs for new security issues
4. **Retry/Add Tasks**: Adapt to failures or new findings
5. **Generate Report**: Create comprehensive security assessment

## Limitations

- Currently uses simulated tool outputs instead of actual tool execution
- Limited to four security tools (nmap, gobuster, ffuf, sqlmap)
- Sequential task execution without parallelism
- No persistent storage for historical comparison
- No authentication support for scanning protected resources

## Future Improvements

- Add more security tools (Nuclei, OpenVAS, OWASP ZAP)
- Implement actual tool execution with proper sandboxing
- Add parallel task processing
- Develop a web interface with real-time monitoring
- Add persistent storage and historical comparison
- Support authenticated scanning



