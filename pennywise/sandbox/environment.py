"""
Sandbox Environment for PennyWise.
Provides an isolated environment to capture user behavior and testing patterns.
"""

import uuid
import json
import time
import logging
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Callable
from pathlib import Path
from enum import Enum
import threading
from collections import deque

logger = logging.getLogger(__name__)


class ActionType(Enum):
    """Types of user actions captured in the sandbox."""
    # Navigation
    TARGET_SELECTED = "target_selected"
    PAGE_VISITED = "page_visited"
    LINK_CLICKED = "link_clicked"
    
    # Attack actions
    ATTACK_INITIATED = "attack_initiated"
    ATTACK_COMPLETED = "attack_completed"
    PAYLOAD_INJECTED = "payload_injected"
    PAYLOAD_MODIFIED = "payload_modified"
    
    # Analysis actions
    FINDING_REVIEWED = "finding_reviewed"
    FINDING_CONFIRMED = "finding_confirmed"
    FINDING_DISMISSED = "finding_dismissed"
    SEVERITY_CHANGED = "severity_changed"
    
    # Configuration
    CONFIG_CHANGED = "config_changed"
    ATTACK_TYPE_SELECTED = "attack_type_selected"
    SCAN_MODE_CHANGED = "scan_mode_changed"
    
    # Custom
    CUSTOM_PAYLOAD_ADDED = "custom_payload_added"
    NOTES_ADDED = "notes_added"


@dataclass
class SandboxAction:
    """A single captured action in the sandbox."""
    id: str
    session_id: str
    action_type: ActionType
    timestamp: datetime
    data: Dict[str, Any]
    context: Dict[str, Any] = field(default_factory=dict)
    duration_ms: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'session_id': self.session_id,
            'action_type': self.action_type.value,
            'timestamp': self.timestamp.isoformat(),
            'data': self.data,
            'context': self.context,
            'duration_ms': self.duration_ms
        }


@dataclass
class SandboxSession:
    """A sandbox session containing multiple actions."""
    id: str
    started_at: datetime
    ended_at: Optional[datetime] = None
    target_url: Optional[str] = None
    actions: List[SandboxAction] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def duration_seconds(self) -> float:
        if self.ended_at and self.started_at:
            return (self.ended_at - self.started_at).total_seconds()
        elif self.started_at:
            return (datetime.now() - self.started_at).total_seconds()
        return 0
    
    @property
    def action_count(self) -> int:
        return len(self.actions)
    
    def get_actions_by_type(self, action_type: ActionType) -> List[SandboxAction]:
        return [a for a in self.actions if a.action_type == action_type]
    
    def get_attack_sequence(self) -> List[str]:
        """Get the sequence of attack types used in this session."""
        attacks = []
        for action in self.actions:
            if action.action_type == ActionType.ATTACK_INITIATED:
                attack_type = action.data.get('attack_type')
                if attack_type:
                    attacks.append(attack_type)
        return attacks
    
    def get_payload_preferences(self) -> Dict[str, int]:
        """Get frequency of payload types used."""
        payloads = {}
        for action in self.actions:
            if action.action_type in [ActionType.PAYLOAD_INJECTED, ActionType.CUSTOM_PAYLOAD_ADDED]:
                payload = action.data.get('payload', '')
                payload_type = self._categorize_payload(payload)
                payloads[payload_type] = payloads.get(payload_type, 0) + 1
        return payloads
    
    def _categorize_payload(self, payload: str) -> str:
        """Categorize a payload by type."""
        payload_lower = payload.lower()
        if '<script' in payload_lower or 'alert(' in payload_lower or 'onerror' in payload_lower:
            return 'xss'
        elif 'select' in payload_lower or 'union' in payload_lower or "'" in payload:
            return 'sqli'
        elif 'system(' in payload_lower or 'exec(' in payload_lower:
            return 'rce'
        else:
            return 'other'
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'started_at': self.started_at.isoformat(),
            'ended_at': self.ended_at.isoformat() if self.ended_at else None,
            'target_url': self.target_url,
            'duration_seconds': self.duration_seconds,
            'action_count': self.action_count,
            'actions': [a.to_dict() for a in self.actions],
            'metadata': self.metadata
        }


class SandboxEnvironment:
    """
    Isolated sandbox environment for capturing user testing behavior.
    
    Features:
    - Session management
    - Action capture with context
    - Pattern extraction for learning
    - Persistent storage
    """
    
    def __init__(self, 
                 storage_path: str = "./pennywise_data/sandbox",
                 max_actions_per_session: int = 1000,
                 on_action: Optional[Callable[[SandboxAction], None]] = None):
        """
        Initialize the sandbox environment.
        
        Args:
            storage_path: Path to store sandbox data
            max_actions_per_session: Maximum actions to capture per session
            on_action: Callback for new action notifications
        """
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        self.max_actions = max_actions_per_session
        self.on_action = on_action
        
        self._current_session: Optional[SandboxSession] = None
        self._sessions: List[SandboxSession] = []
        self._action_buffer: deque = deque(maxlen=100)
        self._lock = threading.Lock()
        
        # Load existing sessions
        self._load_sessions()
        
        logger.info(f"Sandbox environment initialized at {self.storage_path}")
    
    def start_session(self, target_url: Optional[str] = None, 
                     metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Start a new sandbox session.
        
        Args:
            target_url: Optional target URL for this session
            metadata: Optional metadata for the session
            
        Returns:
            Session ID
        """
        with self._lock:
            # End current session if exists
            if self._current_session:
                self.end_session()
            
            session_id = str(uuid.uuid4())
            self._current_session = SandboxSession(
                id=session_id,
                started_at=datetime.now(),
                target_url=target_url,
                metadata=metadata or {}
            )
            
            logger.info(f"Started sandbox session: {session_id}")
            return session_id
    
    def end_session(self) -> Optional[SandboxSession]:
        """
        End the current session and save it.
        
        Returns:
            The ended session or None
        """
        with self._lock:
            if not self._current_session:
                return None
            
            self._current_session.ended_at = datetime.now()
            session = self._current_session
            
            # Save session
            self._save_session(session)
            self._sessions.append(session)
            
            logger.info(f"Ended sandbox session: {session.id} "
                       f"({session.action_count} actions, "
                       f"{session.duration_seconds:.1f}s)")
            
            self._current_session = None
            return session
    
    def capture_action(self,
                      action_type: ActionType,
                      data: Dict[str, Any],
                      context: Optional[Dict[str, Any]] = None,
                      duration_ms: Optional[int] = None) -> Optional[str]:
        """
        Capture a user action in the current session.
        
        Args:
            action_type: Type of action being captured
            data: Action-specific data
            context: Optional context information
            duration_ms: Optional duration of the action
            
        Returns:
            Action ID or None if no session
        """
        with self._lock:
            if not self._current_session:
                # Auto-start session if needed
                self.start_session()
            
            if len(self._current_session.actions) >= self.max_actions:
                logger.warning("Max actions reached for session")
                return None
            
            action_id = str(uuid.uuid4())[:8]
            action = SandboxAction(
                id=action_id,
                session_id=self._current_session.id,
                action_type=action_type,
                timestamp=datetime.now(),
                data=data,
                context=context or {},
                duration_ms=duration_ms
            )
            
            self._current_session.actions.append(action)
            self._action_buffer.append(action)
            
            # Notify callback
            if self.on_action:
                try:
                    self.on_action(action)
                except Exception as e:
                    logger.error(f"Action callback failed: {e}")
            
            return action_id
    
    def capture_target_selection(self, url: str):
        """Capture target URL selection."""
        if self._current_session:
            self._current_session.target_url = url
        self.capture_action(
            ActionType.TARGET_SELECTED,
            {'url': url}
        )
    
    def capture_attack_start(self, attack_type: str, config: Dict[str, Any] = None):
        """Capture start of an attack."""
        self.capture_action(
            ActionType.ATTACK_INITIATED,
            {'attack_type': attack_type, 'config': config or {}}
        )
    
    def capture_attack_complete(self, attack_type: str, 
                               findings_count: int, 
                               duration_ms: int):
        """Capture completion of an attack."""
        self.capture_action(
            ActionType.ATTACK_COMPLETED,
            {'attack_type': attack_type, 'findings_count': findings_count},
            duration_ms=duration_ms
        )
    
    def capture_payload_used(self, payload: str, 
                            parameter: str,
                            success: bool):
        """Capture a payload injection."""
        self.capture_action(
            ActionType.PAYLOAD_INJECTED,
            {'payload': payload, 'parameter': parameter, 'success': success}
        )
    
    def capture_finding_interaction(self, 
                                   finding_id: str,
                                   action: str,  # 'confirm', 'dismiss', 'modify'
                                   details: Optional[Dict[str, Any]] = None):
        """Capture user interaction with a finding."""
        action_map = {
            'confirm': ActionType.FINDING_CONFIRMED,
            'dismiss': ActionType.FINDING_DISMISSED,
            'review': ActionType.FINDING_REVIEWED
        }
        self.capture_action(
            action_map.get(action, ActionType.FINDING_REVIEWED),
            {'finding_id': finding_id, **(details or {})}
        )
    
    def capture_custom_payload(self, payload: str, 
                              attack_type: str,
                              description: str = ""):
        """Capture a custom payload added by user."""
        self.capture_action(
            ActionType.CUSTOM_PAYLOAD_ADDED,
            {'payload': payload, 'attack_type': attack_type, 'description': description}
        )
    
    def get_current_session(self) -> Optional[SandboxSession]:
        """Get the current active session."""
        return self._current_session
    
    def get_all_sessions(self) -> List[SandboxSession]:
        """Get all stored sessions."""
        return self._sessions.copy()
    
    def get_session(self, session_id: str) -> Optional[SandboxSession]:
        """Get a specific session by ID."""
        for session in self._sessions:
            if session.id == session_id:
                return session
        return None
    
    def get_recent_actions(self, count: int = 50) -> List[SandboxAction]:
        """Get recent actions from the buffer."""
        return list(self._action_buffer)[-count:]
    
    def extract_patterns(self) -> Dict[str, Any]:
        """
        Extract behavioral patterns from all sessions.
        
        Returns:
            Dictionary of extracted patterns for learning
        """
        if not self._sessions:
            return {}
        
        patterns = {
            'total_sessions': len(self._sessions),
            'total_actions': sum(s.action_count for s in self._sessions),
            'avg_session_duration': sum(s.duration_seconds for s in self._sessions) / len(self._sessions),
            
            # Attack preferences
            'attack_frequency': {},
            'attack_sequences': [],
            
            # Payload preferences
            'payload_types': {},
            'custom_payloads': [],
            
            # Workflow patterns
            'common_workflows': [],
            'time_per_attack': {},
        }
        
        # Aggregate attack frequency
        for session in self._sessions:
            for attack in session.get_attack_sequence():
                patterns['attack_frequency'][attack] = \
                    patterns['attack_frequency'].get(attack, 0) + 1
            
            # Collect attack sequences
            sequence = session.get_attack_sequence()
            if sequence:
                patterns['attack_sequences'].append(sequence)
            
            # Aggregate payload preferences
            payload_prefs = session.get_payload_preferences()
            for ptype, count in payload_prefs.items():
                patterns['payload_types'][ptype] = \
                    patterns['payload_types'].get(ptype, 0) + count
            
            # Collect custom payloads
            custom = session.get_actions_by_type(ActionType.CUSTOM_PAYLOAD_ADDED)
            for action in custom:
                patterns['custom_payloads'].append(action.data.get('payload', ''))
        
        return patterns
    
    def export_for_training(self, output_path: Optional[str] = None) -> str:
        """
        Export session data in a format suitable for model training.
        
        Returns:
            Path to the exported file
        """
        patterns = self.extract_patterns()
        sessions_data = [s.to_dict() for s in self._sessions]
        
        export_data = {
            'exported_at': datetime.now().isoformat(),
            'patterns': patterns,
            'sessions': sessions_data
        }
        
        output = Path(output_path) if output_path else \
                 self.storage_path / f"training_export_{int(time.time())}.json"
        
        with open(output, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        logger.info(f"Exported training data to {output}")
        return str(output)
    
    def _save_session(self, session: SandboxSession):
        """Save a session to disk."""
        try:
            session_file = self.storage_path / f"session_{session.id}.json"
            with open(session_file, 'w') as f:
                json.dump(session.to_dict(), f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save session: {e}")
    
    def _load_sessions(self):
        """Load existing sessions from disk."""
        try:
            for session_file in self.storage_path.glob("session_*.json"):
                with open(session_file, 'r') as f:
                    data = json.load(f)
                
                session = SandboxSession(
                    id=data['id'],
                    started_at=datetime.fromisoformat(data['started_at']),
                    ended_at=datetime.fromisoformat(data['ended_at']) if data.get('ended_at') else None,
                    target_url=data.get('target_url'),
                    metadata=data.get('metadata', {})
                )
                
                # Reconstruct actions
                for action_data in data.get('actions', []):
                    action = SandboxAction(
                        id=action_data['id'],
                        session_id=action_data['session_id'],
                        action_type=ActionType(action_data['action_type']),
                        timestamp=datetime.fromisoformat(action_data['timestamp']),
                        data=action_data.get('data', {}),
                        context=action_data.get('context', {}),
                        duration_ms=action_data.get('duration_ms')
                    )
                    session.actions.append(action)
                
                self._sessions.append(session)
            
            logger.info(f"Loaded {len(self._sessions)} existing sessions")
            
        except Exception as e:
            logger.error(f"Failed to load sessions: {e}")
    
    def clear_sessions(self):
        """Clear all stored sessions."""
        with self._lock:
            self._sessions = []
            self._current_session = None
            self._action_buffer.clear()
            
            # Remove session files
            for session_file in self.storage_path.glob("session_*.json"):
                session_file.unlink()
            
            logger.info("Cleared all sandbox sessions")
