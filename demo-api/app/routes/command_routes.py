"""Command Injection testing routes."""

from fastapi import APIRouter, HTTPException, Request
import subprocess
import time
import os
from app.utils import add_response_metadata

router = APIRouter()

# 🔴 VULNERABLE: Command injection
@router.get("/exec/vulnerable")
async def command_exec_vulnerable(request: Request, cmd: str):
    """
    🔴 VULNERABLE: Command execution without sanitization.
    
    Allows arbitrary command execution.
    
    Test payloads:
    - cmd=echo hello
    - cmd=echo hello; whoami
    - cmd=echo hello && cat /etc/passwd
    - cmd=sleep 5
    """
    try:
        # Simulate command execution (sandboxed for safety)
        # In real vulnerability, this would use subprocess.run(cmd, shell=True)
        
        # Simulate sleep command
        if "sleep" in cmd.lower():
            try:
                duration = int(cmd.split("sleep")[1].strip().split()[0])
                duration = min(duration, 10)  # Cap at 10 seconds
                time.sleep(duration)
                output = f"Slept for {duration} seconds"
            except:
                output = "Sleep command executed"
        
        # Simulate whoami
        elif "whoami" in cmd.lower():
            output = "www-data"
        
        # Simulate cat /etc/passwd
        elif "cat" in cmd.lower() and "passwd" in cmd.lower():
            output = "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin"
        
        # Simulate echo
        elif "echo" in cmd.lower():
            try:
                output = cmd.split("echo")[1].strip()
            except:
                output = "echo executed"
        
        # Simulate ls
        elif "ls" in cmd.lower():
            output = "app.py\nconfig.py\ndata\nrequirements.txt"
        
        else:
            output = f"Command executed: {cmd}"
        
        return add_response_metadata({
            "command": cmd,
            "output": output,
            "status": "success"
        }, request.state.request_id)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Execution error: {str(e)}")

# 🟢 SECURE: Command execution with whitelist
@router.get("/exec/secure")
async def command_exec_secure(request: Request, cmd: str):
    """
    🟢 SECURE: Command execution with whitelist.
    
    Only allows specific safe commands.
    """
    # Whitelist of allowed commands
    allowed_commands = ["echo", "date", "uptime"]
    
    # Extract base command
    base_cmd = cmd.split()[0] if cmd else ""
    
    if base_cmd not in allowed_commands:
        raise HTTPException(
            status_code=400,
            detail=f"Command not allowed. Allowed: {', '.join(allowed_commands)}"
        )
    
    try:
        # Execute only whitelisted commands
        if base_cmd == "echo":
            output = cmd.split("echo")[1].strip() if "echo" in cmd else ""
        elif base_cmd == "date":
            from datetime import datetime
            output = datetime.utcnow().isoformat()
        elif base_cmd == "uptime":
            output = f"System uptime: {time.time()} seconds"
        else:
            output = "Command executed"
        
        return add_response_metadata({
            "command": cmd,
            "output": output,
            "status": "success"
        }, request.state.request_id)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Execution error: {str(e)}")

# Ping endpoint (vulnerable)
@router.get("/ping")
async def ping(request: Request, host: str):
    """
    🔴 VULNERABLE: Ping command with injection.
    
    Test payloads:
    - host=google.com
    - host=google.com; whoami
    - host=google.com && cat /etc/passwd
    """
    try:
        # Simulate ping with command injection
        if ";" in host or "&&" in host or "|" in host:
            # Command injection detected
            parts = host.replace(";", " ").replace("&&", " ").replace("|", " ").split()
            
            if "whoami" in parts:
                output = "PING google.com: 64 bytes from 142.250.185.46\nwww-data"
            elif "cat" in parts:
                output = "PING google.com: 64 bytes from 142.250.185.46\nroot:x:0:0:root:/root:/bin/bash"
            else:
                output = f"PING {host}: Command injection executed"
        else:
            output = f"PING {host}: 64 bytes from 142.250.185.46: icmp_seq=1 ttl=117 time=10.2 ms"
        
        return add_response_metadata({
            "host": host,
            "output": output
        }, request.state.request_id)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ping error: {str(e)}")
