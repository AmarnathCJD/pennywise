"""
Interactive Training System for PennyWise
==========================================

Records user interactions in real-time and uses them for reinforcement learning.
Creates a live simulation environment where the AI learns from expert pentester actions.
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class UserAction:
    """A single user action during testing."""
    timestamp: str
    action_type: str  # 'select_attack', 'modify_payload', 'target_input', 'verify_result'
    target_url: str
    attack_type: str
    payload: str
    success: bool
    response_code: int
    response_time: float
    notes: str = ""
    
    def to_dict(self):
        return asdict(self)


@dataclass
class TrainingSession:
    """A complete training session."""
    session_id: str
    start_time: str
    end_time: Optional[str]
    target: str
    actions: List[UserAction]
    findings: List[Dict[str, Any]]
    success_rate: float
    total_actions: int
    
    def to_dict(self):
        return {
            'session_id': self.session_id,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'target': self.target,
            'actions': [a.to_dict() for a in self.actions],
            'findings': self.findings,
            'success_rate': self.success_rate,
            'total_actions': self.total_actions
        }


class InteractiveTrainer:
    """
    Interactive trainer that records user actions in real-time.
    
    Features:
    - Live action recording
    - Pattern recognition
    - Success prediction
    - Attack sequence optimization
    """
    
    def __init__(self, storage_path: str = "./pennywise_data/training_sessions"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        self.active_sessions: Dict[str, TrainingSession] = {}
        self.current_session_id: Optional[str] = None
        self.action_patterns: List[List[str]] = []
        self.success_sequences: Dict[str, int] = {}
        
        logger.info("🎯 Interactive Trainer initialized")
    
    def start_session(self, target: str) -> str:
        """Start a new training session."""
        session_id = f"train_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        session = TrainingSession(
            session_id=session_id,
            start_time=datetime.now().isoformat(),
            end_time=None,
            target=target,
            actions=[],
            findings=[],
            success_rate=0.0,
            total_actions=0
        )
        
        self.active_sessions[session_id] = session
        self.current_session_id = session_id
        logger.info(f"🎮 Started training session: {session_id} for target: {target}")
        
        return session_id
    
    def record_action(self, 
                     attack_type: str = None,
                     payload: str = None, 
                     target_url: str = "",
                     success: bool = False,
                     response_time: float = 0.0,
                     result_data: Dict = None,
                     session_id: str = None, 
                     action: UserAction = None):
        """Record a user action."""
        if session_id not in self.active_sessions:
            logger.warning(f"Session {session_id} not found")
            return
        
        session = self.active_sessions[session_id]
        session.actions.append(action)
        session.total_actions += 1
        
        # Update success rate
        successful_actions = sum(1 for a in session.actions if a.success)
        session.success_rate = successful_actions / session.total_actions if session.total_actions > 0 else 0
        
        # Learn patterns
        self._learn_from_action(action)
        
        logger.debug(f"📝 Recorded action: {action.action_type} - Success: {action.success}")
    
    def _learn_from_action(self, action: UserAction):
        """Learn patterns from user actions."""
        # Track successful attack sequences
        if action.success:
            sequence_key = f"{action.attack_type}:{action.payload[:50]}"
            self.success_sequences[sequence_key] = self.success_sequences.get(sequence_key, 0) + 1
    
    def add_finding(self, session_id: str, finding: Dict[str, Any]):
        """Add a finding to the session."""
        if session_id not in self.active_sessions:
            return
        
        session = self.active_sessions[session_id]
        session.findings.append(finding)
        
        logger.info(f"✅ Finding added to session {session_id}: {finding.get('title', 'Unknown')}")
    
    def end_session(self, session_id: str = None) -> Dict[str, Any]:
        """End a training session and save results."""
        if session_id is None:
            session_id = self.current_session_id
        
        if not session_id or session_id not in self.active_sessions:
            return {'error': 'Session not found'}
        
        session = self.active_sessions[session_id]
        session.end_time = datetime.now().isoformat()
        
        # Save session
        session_file = self.storage_path / f"{session_id}.json"
        with open(session_file, 'w') as f:
            json.dump(session.to_dict(), f, indent=2)
        
        # Generate insights
        insights = self._generate_insights(session)
        
        # Remove from active
        del self.active_sessions[session_id]
        if self.current_session_id == session_id:
            self.current_session_id = None
        
        logger.info(f"🎬 Session {session_id} ended. Success rate: {session.success_rate:.1%}")
        
        return {
            'session_id': session_id,
            'duration': (datetime.fromisoformat(session.end_time) - 
                        datetime.fromisoformat(session.start_time)).total_seconds(),
            'total_actions': session.total_actions,
            'findings': len(session.findings),
            'success_rate': session.success_rate,
            'insights': insights
        }
    
    def _generate_insights(self, session: TrainingSession) -> Dict[str, Any]:
        """Generate learning insights from session."""
        if not session.actions:
            return {}
        
        # Analyze attack type preferences
        attack_counts = {}
        for action in session.actions:
            attack_counts[action.attack_type] = attack_counts.get(action.attack_type, 0) + 1
        
        # Find most successful payloads
        successful_payloads = [a.payload for a in session.actions if a.success]
        
        # Calculate average response time
        avg_response_time = sum(a.response_time for a in session.actions) / len(session.actions)
        
        return {
            'preferred_attacks': sorted(attack_counts.items(), key=lambda x: x[1], reverse=True)[:3],
            'successful_payloads': len(set(successful_payloads)),
            'avg_response_time': round(avg_response_time, 3),
            'quick_wins': sum(1 for a in session.actions if a.success and a.response_time < 1.0),
            'learning_score': min(100, int(session.success_rate * 100 + len(session.findings) * 10))
        }
    
    def get_recommendations(self, target: str, attack_type: str) -> List[str]:
        """Get payload recommendations based on learned patterns."""
        recommendations = []
        
        # Find successful sequences for this attack type
        for seq_key, count in sorted(self.success_sequences.items(), key=lambda x: x[1], reverse=True):
            if seq_key.startswith(f"{attack_type}:"):
                payload = seq_key.split(':', 1)[1]
                recommendations.append(payload)
                if len(recommendations) >= 5:
                    break
        
        return recommendations
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get overall training statistics."""
        all_sessions = list(self.storage_path.glob("train_*.json"))
        
        total_actions = 0
        total_findings = 0
        total_success = 0
        
        for session_file in all_sessions:
            try:
                with open(session_file) as f:
                    data = json.load(f)
                    total_actions += data.get('total_actions', 0)
                    total_findings += len(data.get('findings', []))
                    total_success += data.get('success_rate', 0)
            except:
                continue
        
        num_sessions = len(all_sessions)
        
        return {
            'total_sessions': num_sessions,
            'total_actions': total_actions,
            'total_findings': total_findings,
            'avg_success_rate': (total_success / num_sessions) if num_sessions > 0 else 0,
            'learned_patterns': len(self.success_sequences),
            'active_sessions': len(self.active_sessions)
        }


# Global trainer instance
_trainer: Optional[InteractiveTrainer] = None


def get_trainer() -> InteractiveTrainer:
    """Get or create the global trainer instance."""
    global _trainer
    if _trainer is None:
        _trainer = InteractiveTrainer()
    return _trainer
