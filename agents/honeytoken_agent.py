import os
import json
import time
import hashlib
from datetime import datetime
from typing import List, Dict, Any
import random
import string

class HoneytokenAgent:
    """Agent for creating and monitoring honeytokens (decoy files)."""
    
    def __init__(self, base_dir: str = "honeytokens"):
        self.base_dir = base_dir
        self.log_file = "logs/honeytokens.log"
        self.state_file = os.path.join(base_dir, ".honeytoken_state.json")
        self._ensure_dirs()
        self._load_state()
    
    def _ensure_dirs(self):
        """Create honeytokens directory and logs directory."""
        os.makedirs(self.base_dir, exist_ok=True)
        os.makedirs("logs", exist_ok=True)
        # Ensure log file exists
        if not os.path.exists(self.log_file):
            with open(self.log_file, "w") as f:
                f.write("")
    
    def _load_state(self):
        """Load honeytoken state from disk."""
        self.state = {"last_check_time": 0, "tokens": {}}
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, "r") as f:
                    self.state = json.load(f)
            except Exception:
                self._log("Failed to load honeytoken state, starting fresh")
    
    def _save_state(self):
        """Save honeytoken state to disk."""
        try:
            with open(self.state_file, "w") as f:
                json.dump(self.state, f, indent=2)
        except Exception as e:
            self._log(f"Failed to save honeytoken state: {e}")
    
    def _log(self, message: str):
        """Log honeytoken events."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        try:
            with open(self.log_file, "a") as f:
                f.write(log_entry)
        except Exception:
            pass  # Silent fail to avoid crashes
    
    def _generate_token_id(self) -> str:
        """Generate a unique token ID."""
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
    
    def _generate_secret_marker(self) -> str:
        """Generate a unique secret marker."""
        return f"TOKEN_SECRET_{self._generate_token_id()}"
    
    def _get_file_hash(self, filepath: str) -> str:
        """Get SHA256 hash of file."""
        try:
            with open(filepath, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return ""
    
    def create_tokens(self, base_dir: str = "honeytokens") -> List[Dict[str, Any]]:
        """Create honeytoken files."""
        self.base_dir = base_dir
        self._ensure_dirs()
        
        token_templates = {
            "wifi_passwords.txt": """# WiFi Passwords Backup
Network: HomeNetwork_5G
Password: MyWifiPass123!@#
Security: WPA2
Last Updated: {date}
Token ID: {token_id}
Secret Marker: {secret}
""",
            "router_backup.cfg": """# Router Configuration Backup
# Generated on {date}
router_id: ASUS_RT-AC68U
admin_password: AdminPass789!
wan_ip: 192.168.1.1
wifi_ssid: HomeNetwork
wifi_pass: MyWifiPass123!@#
token_id: {token_id}
secret_marker: {secret}
""",
            "admin_creds.txt": """# Admin Credentials Backup
# Exported: {date}
Username: administrator
Password: AdminPass789!
Email: admin@homelan.local
token_id: {token_id}
secret_marker: {secret}
""",
            "smart_camera_config.ini": """[Camera_Config]
model: SmartCam_X1
firmware: 4.2.1
admin_user: admin
admin_pass: CameraPass456!
wifi_ssid: HomeNetwork
wifi_pass: MyWifiPass123!@#
token_id: {token_id}
secret_marker: {secret}
timestamp: {date}
"""
        }
        
        created_tokens = []
        current_time = time.time()
        
        for filename, template in token_templates.items():
            token_id = self._generate_token_id()
            secret = self._generate_secret_marker()
            filepath = os.path.join(self.base_dir, filename)
            
            # Skip if token already exists
            if filename in self.state.get("tokens", {}):
                continue
            
            content = template.format(
                date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                token_id=token_id,
                secret=secret
            )
            
            try:
                with open(filepath, "w") as f:
                    f.write(content)
                
                token_info = {
                    "token_id": token_id,
                    "filename": filename,
                    "path": filepath,
                    "created_at": current_time,
                    "secret_marker": secret,
                    "hash": self._get_file_hash(filepath),
                    "last_accessed": current_time  # Initialize with creation time
                }
                
                self.state["tokens"][filename] = token_info
                created_tokens.append(token_info)
                
                self._log(f"Created honeytoken: {filename} (ID: {token_id})")
                
            except Exception as e:
                self._log(f"Failed to create honeytoken {filename}: {e}")
        
        self._save_state()
        return created_tokens
    
    def list_tokens(self) -> List[Dict[str, Any]]:
        """List all honeytokens."""
        tokens = []
        for filename, token_info in self.state.get("tokens", {}).items():
            tokens.append({
                "token_id": token_info.get("token_id", "UNKNOWN"),
                "filename": filename,
                "created_at": token_info.get("created_at", 0),
                "path": token_info.get("path", ""),
                "last_accessed": token_info.get("last_accessed", 0)
            })
        return tokens
    
    def check_trips(self) -> List[Dict[str, Any]]:
        """Check for honeytoken trips."""
        trips = []
        current_time = time.time()
        last_check = self.state.get("last_check_time", 0)
        
        for filename, token_info in self.state.get("tokens", {}).items():
            filepath = token_info.get("path", "")
            if not os.path.exists(filepath):
                continue
            
            trip_detected = False
            trip_reason = ""
            
            # Check access time (atime)
            try:
                stat_info = os.stat(filepath)
                atime = stat_info.st_atime
                mtime = stat_info.st_mtime
                
                # Check if accessed since last check
                if atime > last_check:
                    trip_detected = True
                    trip_reason = "File accessed (atime)"
                
                # Check if modified (tampered)
                current_hash = self._get_file_hash(filepath)
                stored_hash = token_info.get("hash", "")
                if current_hash != stored_hash:
                    trip_detected = True
                    trip_reason = "File modified (hash mismatch)"
                
                # Check if mtime changed but atime didn't (some systems don't update atime)
                if mtime > token_info.get("last_accessed", 0) and not trip_detected:
                    trip_detected = True
                    trip_reason = "File modified (mtime)"
                
            except Exception as e:
                self._log(f"Error checking {filename}: {e}")
                continue
            
            if trip_detected:
                trip_event = {
                    "token_id": token_info.get("token_id", "UNKNOWN"),
                    "filename": filename,
                    "path": filepath,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "severity": "HIGH",
                    "reason": f"Honeytoken accessed: {trip_reason}",
                    "recommended_action": ["ALERT", "BLOCK_IP"]
                }
                
                trips.append(trip_event)
                
                # Update last accessed time
                self.state["tokens"][filename]["last_accessed"] = current_time
                self.state["tokens"][filename]["hash"] = self._get_file_hash(filepath)
                
                self._log(f"Honeytoken trip detected: {filename} - {trip_reason}")
        
        # Update last check time
        self.state["last_check_time"] = current_time
        self._save_state()
        
        return trips
    
    def manual_trip(self, token_id: str) -> Dict[str, Any]:
        """Manually trigger a honeytoken trip for demo."""
        # Find token by ID
        target_token = None
        for filename, token_info in self.state.get("tokens", {}).items():
            if token_info.get("token_id") == token_id:
                target_token = token_info
                target_token["filename"] = filename
                break
        
        if not target_token:
            return {
                "ok": False,
                "message": f"Token ID {token_id} not found"
            }
        
        trip_event = {
            "token_id": token_id,
            "filename": target_token["filename"],
            "path": target_token.get("path", ""),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "severity": "HIGH",
            "reason": "Honeytoken accessed: Manual trip (demo)",
            "recommended_action": ["ALERT", "BLOCK_IP"]
        }
        
        self._log(f"Manual honeytoken trip: {token_id}")
        
        return {
            "ok": True,
            "trip": trip_event
        }
    
    def status(self) -> Dict[str, Any]:
        """Get honeytoken agent status."""
        return {
            "num_tokens": len(self.state.get("tokens", {})),
            "base_dir": self.base_dir,
            "last_check_time": self.state.get("last_check_time", 0),
            "last_check_formatted": datetime.fromtimestamp(self.state.get("last_check_time", 0)).strftime("%Y-%m-%d %H:%M:%S") if self.state.get("last_check_time", 0) > 0 else "Never",
            "log_file": self.log_file,
            "state_file": self.state_file
        }
