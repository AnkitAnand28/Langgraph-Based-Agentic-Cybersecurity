from typing import Dict, List, Optional, Any, Tuple, Set, Annotated
import os
import re
import subprocess
import ipaddress
from pydantic import BaseModel, Field
import json
import time
from datetime import datetime
from dotenv import load_dotenv
from langchain_ollama.llms import OllamaLLM
from langchain_groq import ChatGroq

from langchain_core.tools import tool
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_community.llms import LlamaCpp
from langchain.agents import AgentExecutor, create_react_agent
from langgraph.graph import StateGraph, END
from langgraph.graph import StateGraph

load_dotenv()
os.environ['GROQ_API_KEY']=os.getenv("GROQ_API_KEY")
groq_api_key=os.getenv("GROQ_API_KEY")

class NmapScanInput(BaseModel):
    target: str
    scan_type: str = Field(default="-sS")
    ports: str = Field(default="1-1000")

class GobusterInput(BaseModel):
    target: str
    wordlist: str = Field(default="/usr/share/wordlists/dirb/common.txt")

class FfufInput(BaseModel):
    target: str
    wordlist: str = Field(default="/usr/share/wordlists/dirb/common.txt")
    extensions: str = Field(default="php,html,txt")

class SqlmapInput(BaseModel):
    target: str
    parameters: str = Field(default="")
    risk: int = Field(default=1)
    level: int = Field(default=1)

class ScopeConfig(BaseModel):
    """Configuration for the scope of security scans"""
    domains: List[str] = Field(default_factory=list, description="List of allowed domains (can include wildcards)")
    ip_ranges: List[str] = Field(default_factory=list, description="List of allowed IP ranges in CIDR notation")

class Task(BaseModel):
    """A security task to be executed"""
    id: str
    description: str
    tool: str
    parameters: Dict[str, Any]
    status: str = "pending" 
    result: Optional[Dict[str, Any]] = None
    retry_count: int = 0
    max_retries: int = 3
    
class SecurityState(BaseModel):
    """The state of the security pipeline"""
    original_request: str
    scope: ScopeConfig
    tasks: List[Task] = Field(default_factory=list)
    current_task_index: int = 0
    completed_tasks: List[str] = Field(default_factory=list)
    execution_logs: List[Dict[str, Any]] = Field(default_factory=list)
    final_report: Optional[Dict[str, Any]] = None
    task_addition_count: int = 0 

@tool
def run_nmap_scan(input: NmapScanInput) -> str:
    """Run an nmap scan on a target
    
    Args:
        input: NmapScanInput containing:
            - target: Domain or IP to scan
            - scan_type: Type of scan to run (e.g., -sS for SYN scan)
            - ports: Port range to scan
        
    Returns:
        Output from nmap scan
    """
    
    print(f"Running nmap {input.scan_type} -p {input.ports} {input.target}")
    
    if input.target == "google.com":
        return """
        Starting Nmap 7.92 ( https://nmap.org )
        Nmap scan report for google.com (142.250.190.78)
        Host is up (0.0087s latency).
        Not shown: 995 filtered tcp ports (no-response)
        PORT    STATE SERVICE
        80/tcp  open  http
        443/tcp open  https
        
        Nmap done: 1 IP address (1 host up) scanned in 5.21 seconds
        """

    return f"""
    Starting Nmap 7.92 ( https://nmap.org )
    Nmap scan report for {input.target}
    Host is up (0.015s latency).
    Not shown: 996 closed tcp ports (reset)
    PORT    STATE SERVICE
    22/tcp  open  ssh
    80/tcp  open  http
    443/tcp open  https
    8080/tcp open  http-proxy
    
    Nmap done: 1 IP address (1 host up) scanned in 2.34 seconds
    """

@tool
def run_gobuster(input: GobusterInput) -> str:
    """Run gobuster directory scan on a target
    
    Args:
        input: GobusterInput containing:
            - target: URL to scan
            - wordlist: Path to wordlist for directory brute forcing
        
    Returns:
        Output from gobuster scan
    """
    print(f"Running gobuster dir -u {input.target} -w {input.wordlist}")
    
    return f"""
    ===============================================================
    Gobuster v3.1.0
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
    ===============================================================
    [+] Url:                     {input.target}
    [+] Method:                  GET
    [+] Threads:                 10
    [+] Wordlist:                {input.wordlist}
    [+] Negative Status codes:   404
    [+] User Agent:              gobuster/3.1.0
    [+] Timeout:                 10s
    ===============================================================
    2023/04/20 12:34:56 Starting gobuster in directory enumeration mode
    ===============================================================
    /admin                (Status: 302) [Size: 219] [--> /login]
    /api                  (Status: 200) [Size: 45]
    /assets               (Status: 301) [Size: 178] [--> /assets/]
    /images               (Status: 301) [Size: 178] [--> /images/]
    /login                (Status: 200) [Size: 3752]
    /logout               (Status: 302) [Size: 219] [--> /login]
    /scripts              (Status: 301) [Size: 178] [--> /scripts/]
    /uploads              (Status: 301) [Size: 178] [--> /uploads/]
    ===============================================================
    2023/04/20 12:36:45 Finished
    ===============================================================
    """

@tool
def run_ffuf(input: FfufInput) -> str:
    """Run ffuf web fuzzer on a target
    
    Args:
        input: FfufInput containing:
            - target: URL to scan (include FUZZ keyword where fuzzing should occur)
            - wordlist: Path to wordlist
            - extensions: File extensions to check
        
    Returns:
        Output from ffuf scan
    """
    print(f"Running ffuf -u {input.target} -w {input.wordlist} -e .{input.extensions.replace(',', ',.').replace(' ', '')}")
    
    return f"""
    {'':39}FFUF - Fuzz Faster U Fool - v1.5.0
    
    {'':39}:: Method           : GET
    {'':39}:: URL              : {input.target}
    {'':39}:: Wordlist         : {input.wordlist}
    {'':39}:: Extensions       : {input.extensions}
    {'':39}:: Follow redirects : false
    {'':39}:: Calibration      : false
    {'':39}:: Timeout          : 10
    {'':39}:: User-agent       : ffuf/1.5.0
    {'':39}:: Threads          : 10
    
    :: Progress: [4614/4614] :: Job [1/1] :: 52 req/sec :: Duration: [0:01:29] :: Errors: 0 ::
    
    admin                   [Status: 302, Size: 219, Words: 22, Lines: 4, Duration: 127ms]
    api                     [Status: 200, Size: 45, Words: 5, Lines: 1, Duration: 129ms]
    config.php              [Status: 200, Size: 0, Words: 0, Lines: 0, Duration: 132ms]
    login                   [Status: 200, Size: 3752, Words: 938, Lines: 87, Duration: 133ms]
    login.php               [Status: 200, Size: 3752, Words: 938, Lines: 87, Duration: 139ms]
    uploads                 [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 142ms]
    index.php               [Status: 200, Size: 9871, Words: 1352, Lines: 267, Duration: 154ms]
    """

@tool
def run_sqlmap(input: SqlmapInput) -> str:
    """Run sqlmap to test for SQL injection vulnerabilities
    
    Args:
        input: SqlmapInput containing:
            - target: URL to scan
            - parameters: Parameters to test (e.g., id=1)
            - risk: Risk level (1-3)
            - level: Level of tests (1-5)
        
    Returns:
        Output from sqlmap scan
    """
    print(f"Running sqlmap -u {input.target}?{input.parameters} --risk={input.risk} --level={input.level} --batch")
    
    if "id=" in input.parameters or "user=" in input.parameters:
        return f"""
        sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:
        ---
        Parameter: {input.parameters.split('=')[0]} (GET)
        Type: boolean-based blind
        Title: AND boolean-based blind - WHERE or HAVING clause
        Payload: {input.parameters} AND 5747=5747
        
        Type: time-based blind
        Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
        Payload: {input.parameters} AND (SELECT 3669 FROM (SELECT(SLEEP(5)))TmtS)
        
        Type: UNION query
        Title: Generic UNION query (NULL) - 3 columns
        Payload: {input.parameters} UNION ALL SELECT NULL,NULL,CONCAT(0x71716a6a71,0x4a4f634e686a76704f654c44706e7a72784a4c7367797553584f75444e6a4f5975756a6f4e66,0x7162707871)-- -
        ---
        """
    else:
        return f"""
        sqlmap did not find any SQL injection vulnerabilities on the tested parameters.
        """

def is_domain_in_scope(domain: str, allowed_domains: List[str]) -> bool:
    """Check if a domain is in the allowed scope"""
    domain = domain.lower()
    
    for allowed in allowed_domains:
        if allowed.startswith("*."):
            suffix = allowed[1:]
            if domain.endswith(suffix):
                return True
        elif allowed == domain:
            return True
    print("domain: ", domain,allowed_domains)
    
    return False

def is_ip_in_scope(ip: str, allowed_ranges: List[str]) -> bool:
    """Check if an IP is in the allowed scope"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        
        for cidr in allowed_ranges:
            if ip_obj in ipaddress.ip_network(cidr):
                return True
    except ValueError:
        return False
    
    return False

def validate_target_in_scope(target: str, scope: ScopeConfig) -> bool:
    """Validate if a target is within the defined scope"""
    try:
        ipaddress.ip_address(target)
        return is_ip_in_scope(target, scope.ip_ranges)
    except ValueError:
        domain = target
        if '://' in domain:
            domain = domain.split('://', 1)[1]
        if '/' in domain:
            domain = domain.split('/', 1)[0]
        if ':' in domain:
            domain = domain.split(':', 1)[0]
            
        return is_domain_in_scope(domain, scope.domains)


def initialize_task_list(state: SecurityState) -> SecurityState:
    """Initialize the task list based on the original request"""
    llm=ChatGroq(groq_api_key=groq_api_key,model_name="Llama3-8b-8192")
    
    task_prompt = ChatPromptTemplate.from_template(
        """
        You are a cybersecurity expert tasked with breaking down a high-level security task into specific executable steps.
        
        The user has requested: {original_request}
        
        Create a list of specific security tasks that should be executed in sequence to fulfill this request.
        Each task should use one of the following tools:
        - nmap: For network scanning and port discovery
        - gobuster: For directory brute-forcing
        - ffuf: For web fuzzing
        - sqlmap: For SQL injection testing
        
        For each task, provide:
        1. A short description
        2. The tool to use
        3. The specific parameters for that tool
        
        Format your response as a JSON list of tasks, with each task having these fields:
        - id: A unique identifier for the task (e.g., "task1", "task2")
        - description: A brief description of what the task does
        - tool: The name of the tool to use (must be one of: "nmap", "gobuster", "ffuf", "sqlmap")
        - parameters: An object containing the parameters for the tool
        
        IMPORTANT: Please limit the total number of tasks to no more than 5.
        
        Only include the JSON list in your response, nothing else.
        """
    )

    task_chain = task_prompt | llm | StrOutputParser()
    task_json = task_chain.invoke({"original_request": state.original_request})
    
    try:
        tasks_data = json.loads(task_json)
        tasks_data = tasks_data[:5]  
        tasks = []
        for task_data in tasks_data:
            tasks.append(Task(**task_data))
        
        state.tasks = tasks
        return state
    except Exception as e:
        state.execution_logs.append({
            "timestamp": datetime.now().isoformat(),
            "event": "task_initialization_error",
            "error": str(e)
        })
        return state

def execute_current_task(state: SecurityState) -> SecurityState:
    """Execute the current task in the queue"""
    if state.current_task_index >= len(state.tasks):
        return state
    
    current_task = state.tasks[state.current_task_index]
    current_task.status = "in_progress"
    
    state.execution_logs.append({
        "timestamp": datetime.now().isoformat(),
        "event": "task_execution_start",
        "task_id": current_task.id,
        "description": current_task.description
    })
    severity_map={
        "high":3,
        "medium":2,
        "low":1,
        1:1,
        2:2,
        3:3,
        "1":1,
        "2":2,
        "3":3
    }
    
    try:
        if current_task.tool in ["nmap", "gobuster", "ffuf", "sqlmap"]:
            target_param = ""
            if current_task.tool == "nmap":
                target_param = current_task.parameters.get("target", "")
            elif current_task.tool == "gobuster":
                target_param = current_task.parameters.get("target", "")
            elif current_task.tool == "ffuf":
                target_param = current_task.parameters.get("target", "")
            elif current_task.tool == "sqlmap":
                target_param = current_task.parameters.get("target", "")

                
            if target_param and not validate_target_in_scope(target_param, state.scope):
                raise ValueError(f"Target {target_param} is out of the defined scope")
        
        result = ""
        if current_task.tool == "nmap":
            input_data = NmapScanInput(
                target=current_task.parameters.get("target", ""),
                scan_type=current_task.parameters.get("scan_type", "-sS"),
                ports=current_task.parameters.get("ports", "1-1000")
            )
            result = run_nmap_scan.invoke({"input": input_data.model_dump()})
        elif current_task.tool == "gobuster":
            input_data = GobusterInput(
                target=current_task.parameters.get("target", ""),
                wordlist=current_task.parameters.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
            )
            result=run_gobuster.invoke({"input":input_data.model_dump()})
        elif current_task.tool == "ffuf":
            input_data = FfufInput(
                target=current_task.parameters.get("target", ""),
                wordlist=current_task.parameters.get("wordlist", "/usr/share/wordlists/dirb/common.txt"),
                extensions=current_task.parameters.get("extensions", "php,html,txt")
            )
            result=run_ffuf.invoke({"input":input_data.model_dump()})
        elif current_task.tool == "sqlmap":
            input_data = SqlmapInput(
                target=current_task.parameters.get("target", ""),
                parameters=current_task.parameters.get("parameters", ""),
                risk=severity_map[current_task.parameters.get("risk", 1)],
                level=current_task.parameters.get("level", 1)
            )
            result=run_sqlmap.invoke({"input":input_data.model_dump()})
        else:
            raise ValueError(f"Unknown tool: {current_task.tool}")
        
        current_task.result = {"output": result, "status": "success"}
        current_task.status = "completed"
        state.completed_tasks.append(current_task.id)
        
        state.execution_logs.append({
            "timestamp": datetime.now().isoformat(),
            "event": "task_execution_complete",
            "task_id": current_task.id,
            "success": True
        })
        
    except Exception as e:
        print("Failed at the execution",e)
        current_task.status = "failed"
        current_task.result = {"output": str(e), "status": "failed"}
        current_task.retry_count += 1
        
        state.execution_logs.append({
            "timestamp": datetime.now().isoformat(),
            "event": "task_execution_failed",
            "task_id": current_task.id,
            "error": str(e)
        })
    
    return state


def decide_next_step(state: SecurityState) -> str:
    """Decide the next step in the workflow based on the current state"""
    if state.current_task_index >= len(state.tasks):
        return "generate_report"
    
    current_task = state.tasks[state.current_task_index]
    
    if state.task_addition_count > 5 or len(state.tasks) > 20: 
        state.execution_logs.append({
            "timestamp": datetime.now().isoformat(),
            "event": "safety_limit_reached",
            "message": "Task limit reached, moving to report generation"
        })
        state.current_task_index = len(state.tasks)
        return "generate_report"
    
    if current_task.status == "completed":
        return "analyze_results"
    elif current_task.status == "failed":
        if current_task.retry_count < current_task.max_retries:
            return "retry_task"
        else:
            state.current_task_index += 1
            return "execute_task" if state.current_task_index < len(state.tasks) else "generate_report"
    elif current_task.status == "failed_permanently":
        state.current_task_index += 1
        return "execute_task" if state.current_task_index < len(state.tasks) else "generate_report"
    else:
        return "execute_task"
    

def retry_task(state: SecurityState) -> SecurityState:
    """Retry a failed task with modified parameters"""
    current_task = state.tasks[state.current_task_index]
    print(f"retrying {current_task}")
    
    state.execution_logs.append({
        "timestamp": datetime.now().isoformat(),
        "event": "task_retry",
        "task_id": current_task.id,
        "retry_count": current_task.retry_count
    })

    if current_task.retry_count >= current_task.max_retries:
        current_task.status = "failed_permanently"
        state.current_task_index += 1
        return state
    
    if current_task.tool == "nmap":
        scan_types = ["-sS", "-sT", "-sV", "-A"]
        current_scan_type = current_task.parameters.get("scan_type", "-sS")
        next_scan_type = scan_types[(scan_types.index(current_scan_type) + 1) % len(scan_types)]
        current_task.parameters["scan_type"] = next_scan_type
    
    elif current_task.tool == "gobuster" or current_task.tool == "ffuf":
        wordlists = [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/wordlists/wfuzz/general/big.txt"
        ]
        current_wordlist = current_task.parameters.get("wordlist", wordlists[0])
        if current_wordlist in wordlists:
            next_index = (wordlists.index(current_wordlist) + 1) % len(wordlists)
            next_wordlist = wordlists[next_index]
        else:
            next_wordlist = wordlists[0]

        current_task.parameters["wordlist"] = next_wordlist
    
    elif current_task.tool == "sqlmap":
        current_risk = current_task.parameters.get("risk", 1)
        current_level = current_task.parameters.get("level", 1)
        current_task.parameters["risk"] = min(3, current_risk + 1)
        current_task.parameters["level"] = min(5, current_level + 1)
    
    current_task.status = "pending"
    
    return state

def analyze_results(state: SecurityState) -> SecurityState:
    """Analyze the results of the current task and potentially add new tasks"""
    current_task = state.tasks[state.current_task_index]
    
    state.current_task_index += 1
    
    if not current_task.result or current_task.result.get("status") != "success":
        return state
    
    state.task_addition_count += 1

    if len(state.tasks) >= 15:
        state.execution_logs.append({
            "timestamp": datetime.now().isoformat(),
            "event": "task_limit_reached",
            "message": "Maximum number of tasks reached, stopping analysis"
        })
        return state
    
    if state.task_addition_count >= 3:
        state.execution_logs.append({
            "timestamp": datetime.now().isoformat(),
            "event": "task_analysis_skipped",
            "reason": "Maximum task addition rounds reached"
        })
        return state
    
    llm=ChatGroq(groq_api_key=groq_api_key,model_name="Llama3-8b-8192")
    
    analysis_prompt = ChatPromptTemplate.from_template(
        """
        You are a cybersecurity expert analyzing the results of a security scan.
        
        The original security request was: {original_request}
        
        The following task was executed:
        Task ID: {task_id}
        Description: {task_description}
        Tool: {task_tool}
        
        Here is the output of the scan:
        {task_output}
        
        Based on these results, determine if additional security tasks should be added to the task list.
        Consider:
        1. If new potential vulnerabilities were found that should be investigated
        2. If new attack surfaces were discovered that need scanning
        3. If the results suggest other types of scans that would be valuable
        
        IMPORTANT: Be highly selective and only add tasks that are absolutely necessary.
        Limit your response to a maximum of 2 additional tasks.
        
        Format your response as a JSON list of new tasks to add (can be empty if no new tasks are needed),
        with each task having these fields:
        - id: A unique identifier for the task (e.g., "task{next_task_id}", "task{{next_task_id+1}}")
        - description: A brief description of what the task does
        - tool: The name of the tool to use (must be one of: "nmap", "gobuster", "ffuf", "sqlmap")
        - parameters: An object containing the parameters for the tool
        
        Only include the JSON list in your response, nothing else.
        """
    )
    
    analysis_chain = analysis_prompt | llm | StrOutputParser()
    next_task_id = len(state.tasks) + 1
    
    analysis_json = analysis_chain.invoke({
        "original_request": state.original_request,
        "task_id": current_task.id,
        "task_description": current_task.description,
        "task_tool": current_task.tool,
        "task_output": current_task.result.get("output", ""),
        "next_task_id": next_task_id
    })
    
    try:
        new_tasks_data = json.loads(analysis_json)
        new_tasks_data = new_tasks_data[:2]
        
        for task_data in new_tasks_data:
            new_task = Task(**task_data)
            state.tasks.append(new_task)
            
            state.execution_logs.append({
                "timestamp": datetime.now().isoformat(),
                "event": "task_added",
                "task_id": new_task.id,
                "description": new_task.description,
                "based_on_task": current_task.id
            })
    except Exception as e:
        state.execution_logs.append({
            "timestamp": datetime.now().isoformat(),
            "event": "task_analysis_error",
            "error": str(e)
        })
    
    return state

def generate_final_report(state: SecurityState) -> SecurityState:
    """Generate a final report summarizing all findings"""
    llm = ChatGroq(groq_api_key=groq_api_key, model_name="Llama3-8b-8192")
    
    completed_tasks = []
    for task in state.tasks:
        if task.status == "completed" and task.result and task.result.get("status") == "success":
            completed_tasks.append({
                "id": task.id,
                "description": task.description,
                "tool": task.tool,
                "output": task.result.get("output", "")
            })
    
    report_prompt = ChatPromptTemplate.from_template(
        """
        You are a cybersecurity expert creating a comprehensive security report.
        
        The original security request was: {original_request}
        
        The following security tasks were executed:
        {tasks_json}
        
        Create a comprehensive security report that includes:
        1. An executive summary of findings
        2. Key vulnerabilities or security issues discovered
        3. A detailed breakdown of each finding with severity ratings
        4. Recommendations for remediation
        
        Format your response as a JSON object with these sections.
        """
    )
    
    try:
        report_chain = report_prompt | llm | StrOutputParser()
        report_json = report_chain.invoke({
            "original_request": state.original_request,
            "tasks_json": json.dumps(completed_tasks, indent=2)
        })

        state.final_report = {
            "findings": [{"description": "Raw report output", "details": report_json}],
            "recommendations": ["Please review the raw output manually."]
        }
            
        state.execution_logs.append({
            "timestamp": datetime.now().isoformat(),
            "event": "report_generation_json_error",
        })

    except Exception as e:
        state.final_report = {
            "executiveSummary": "Report generation failed.",
            "findings": [{"description": "Error during report generation", "details": str(e)}],
            "recommendations": ["Review individual task outputs manually."]
        }
        
        state.execution_logs.append({
            "timestamp": datetime.now().isoformat(),
            "event": "report_generation_error",
            "error": str(e)
        })
    
    return state

def build_cybersecurity_agent():
    """Build and return the cybersecurity agent graph"""
    workflow = StateGraph(SecurityState)
    
    workflow.add_node("initialize_tasks", initialize_task_list)
    workflow.add_node("execute_task", execute_current_task)
    workflow.add_node("analyze_results", analyze_results)
    workflow.add_node("retry_task", retry_task)
    workflow.add_node("generate_report", generate_final_report)
    
    workflow.add_edge("initialize_tasks", "execute_task")
    workflow.add_conditional_edges(
        "execute_task",
        decide_next_step,
        {
            "analyze_results": "analyze_results",
            "retry_task": "retry_task",
            "execute_task": "execute_task",
            "generate_report": "generate_report"
        }
    )
    workflow.add_edge("analyze_results", "execute_task")
    workflow.add_edge("retry_task","execute_task")
    workflow.add_edge("generate_report", END)
    
    workflow.set_entry_point("initialize_tasks")

    return workflow.compile()


def run_cybersecurity_agent(request: str, scope_config: ScopeConfig, max_execution_time=120):
    """Run the cybersecurity agent with a specific request and scope"""
    initial_state = SecurityState(
        original_request=request,
        scope=scope_config
    )
    
    cybersecurity_agent = build_cybersecurity_agent()
    start_time = time.time()

    try:
        result = cybersecurity_agent.invoke(initial_state, {"recursion_limit": 50})
          
        if time.time() - start_time > max_execution_time:
            if isinstance(result, dict):
                result = SecurityState(**result)
            if not result.final_report:
                result.final_report = {
                    "executiveSummary": "Execution timeout - partial results only",
                    "findings": []
                }

        if isinstance(result, dict):
                result = SecurityState(**result)

        if not result.final_report:
                result = generate_final_report(result)
                
    except Exception as e:
        result = initial_state
        result.execution_logs.append({
            "timestamp": datetime.now().isoformat(),
            "event": "execution_error",
            "error": str(e)
        })
        result.final_report = {
            "executiveSummary": "Execution terminated due to error - partial results only",
            "findings": []
        }
    
    if isinstance(result, dict):
        result = SecurityState(**result)

    if not result.final_report:
        result.final_report = {
            "executiveSummary": "Report generation failed - forcing fallback report",
            "findings": [{"description": "Completed tasks summary", 
                         "details": "\n".join([f"{t.id}: {t.description} - {t.status}" for t in result.tasks])}],
            "recommendations": ["Review individual task outputs manually for security findings."]
        }
    
    return result

if __name__ == "__main__":
    scope = ScopeConfig(
        domains=["google.com"],
        ip_ranges=["45.33.32.156/32"]
    )
    target=scope.domains[0]
    result = run_cybersecurity_agent(
        f"Scan the {target} for open ports and directories",
        scope
    )
    print("Printing result:")
    print(result)
    
    if result.final_report:
        print("Final Report:")
        print(json.dumps(result.final_report, indent=2))
    else:
        print("No final report generated.")
    print("\nExecution Logs:")
    for log in result.execution_logs:
        print(f"{log['timestamp']} - {log['event']}")