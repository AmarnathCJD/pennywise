"""
Behavior Learner for PennyWise.
Reinforcement learning system that adapts to user testing patterns.
"""

import json
import logging
import math
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
from collections import defaultdict
import random

from ..sandbox.environment import SandboxEnvironment, SandboxSession, ActionType
from ..config import AttackType

logger = logging.getLogger(__name__)


@dataclass
class UserPattern:
    """A learned user behavior pattern."""
    pattern_id: str
    pattern_type: str  # attack_preference, workflow, payload_style
    data: Dict[str, Any]
    confidence: float
    frequency: int
    last_seen: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'pattern_id': self.pattern_id,
            'pattern_type': self.pattern_type,
            'data': self.data,
            'confidence': self.confidence,
            'frequency': self.frequency,
            'last_seen': self.last_seen.isoformat()
        }


@dataclass
class LearningState:
    """State of the learning system."""
    patterns: List[UserPattern] = field(default_factory=list)
    attack_weights: Dict[str, float] = field(default_factory=dict)
    payload_rankings: Dict[str, List[str]] = field(default_factory=dict)
    workflow_preferences: Dict[str, float] = field(default_factory=dict)
    training_samples: int = 0
    last_update: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'patterns': [p.to_dict() for p in self.patterns],
            'attack_weights': self.attack_weights,
            'payload_rankings': self.payload_rankings,
            'workflow_preferences': self.workflow_preferences,
            'training_samples': self.training_samples,
            'last_update': self.last_update.isoformat() if self.last_update else None
        }


class BehaviorLearner:
    """
    Reinforcement learning system for adapting to user testing patterns.
    
    Learns:
    - Preferred attack types and sequences
    - Payload effectiveness and preferences
    - Workflow patterns and timing
    - Decision-making patterns
    
    Uses a simple Q-learning inspired approach adapted for pentesting workflows.
    """
    
    # Learning parameters
    LEARNING_RATE = 0.1
    DISCOUNT_FACTOR = 0.9
    EXPLORATION_RATE = 0.2
    
    def __init__(self,
                 model_path: str = "./pennywise_data/learning_model",
                 min_samples: int = 50,
                 sandbox: Optional[SandboxEnvironment] = None):
        """
        Initialize the behavior learner.
        
        Args:
            model_path: Path to store learned model
            min_samples: Minimum samples before adaptation kicks in
            sandbox: Optional sandbox environment to learn from
        """
        self.model_path = Path(model_path)
        self.model_path.mkdir(parents=True, exist_ok=True)
        
        self.min_samples = min_samples
        self.sandbox = sandbox
        
        self.state = LearningState()
        
        # Q-table for attack type decisions
        # State: (target_type, has_forms, has_params) -> Action: attack_type -> Q-value
        self.q_table: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
        
        # Reward history for different actions
        self.reward_history: Dict[str, List[float]] = defaultdict(list)
        
        # Load existing model
        self._load_model()
        
        logger.info(f"Behavior Learner initialized with {self.state.training_samples} samples")
    
    def learn_from_session(self, session: SandboxSession):
        """
        Learn from a completed sandbox session.
        
        Args:
            session: Completed sandbox session
        """
        if session.action_count < 3:
            # Not enough data to learn from
            return
        
        logger.info(f"Learning from session {session.id} ({session.action_count} actions)")
        
        # Extract patterns
        self._learn_attack_preferences(session)
        self._learn_payload_preferences(session)
        self._learn_workflow_patterns(session)
        self._update_q_values(session)
        
        self.state.training_samples += 1
        self.state.last_update = datetime.now()
        
        # Save model periodically
        if self.state.training_samples % 10 == 0:
            self._save_model()
    
    def learn_from_sandbox(self):
        """Learn from all sessions in the connected sandbox."""
        if not self.sandbox:
            logger.warning("No sandbox connected for learning")
            return
        
        sessions = self.sandbox.get_all_sessions()
        for session in sessions:
            if session.ended_at:  # Only learn from completed sessions
                self.learn_from_session(session)
    
    def get_attack_recommendation(self,
                                  target_features: Dict[str, Any]) -> List[Tuple[str, float]]:
        """
        Get attack type recommendations based on learned preferences.
        
        Args:
            target_features: Features of the target (has_forms, has_params, etc.)
            
        Returns:
            List of (attack_type, confidence) tuples, sorted by recommendation strength
        """
        if self.state.training_samples < self.min_samples:
            # Not enough data, return default
            return [
                ('xss', 0.5),
                ('sqli', 0.5),
                ('csrf', 0.3)
            ]
        
        # Get state key for Q-table lookup
        state_key = self._get_state_key(target_features)
        
        # Get Q-values for this state
        q_values = self.q_table.get(state_key, {})
        
        if not q_values:
            # Use learned attack weights as fallback
            weights = self.state.attack_weights
            if weights:
                total = sum(weights.values())
                return [(k, v/total) for k, v in sorted(weights.items(), 
                                                        key=lambda x: x[1], 
                                                        reverse=True)]
            return [('xss', 0.5), ('sqli', 0.5)]
        
        # Normalize Q-values to probabilities
        total = sum(max(0, v) for v in q_values.values()) or 1
        recommendations = [
            (attack, max(0, value) / total)
            for attack, value in sorted(q_values.items(), 
                                       key=lambda x: x[1], 
                                       reverse=True)
        ]
        
        return recommendations
    
    def get_payload_ranking(self, attack_type: str) -> List[str]:
        """
        Get payload ranking for an attack type based on learned effectiveness.
        
        Args:
            attack_type: Attack type (xss, sqli, etc.)
            
        Returns:
            List of payloads sorted by effectiveness
        """
        return self.state.payload_rankings.get(attack_type, [])
    
    def record_reward(self,
                     attack_type: str,
                     target_features: Dict[str, Any],
                     success: bool,
                     finding_count: int = 0,
                     severity_score: float = 0):
        """
        Record a reward for an attack action (for online learning).
        
        Args:
            attack_type: Attack type used
            target_features: Features of the target
            success: Whether attack was successful
            finding_count: Number of findings discovered
            severity_score: Sum of severity scores (critical=4, high=3, etc.)
        """
        # Calculate reward
        reward = 0
        if success:
            reward = 1.0 + (finding_count * 0.5) + (severity_score * 0.2)
        else:
            reward = -0.1  # Small negative reward for unsuccessful attempts
        
        # Update Q-value
        state_key = self._get_state_key(target_features)
        current_q = self.q_table[state_key][attack_type]
        
        # Q-learning update
        new_q = current_q + self.LEARNING_RATE * (reward - current_q)
        self.q_table[state_key][attack_type] = new_q
        
        # Track reward history
        self.reward_history[attack_type].append(reward)
        
        logger.debug(f"Updated Q({state_key}, {attack_type}): {current_q:.2f} -> {new_q:.2f}")
    
    def should_explore(self) -> bool:
        """Determine if we should explore (try new things) or exploit (use learned preferences)."""
        if self.state.training_samples < self.min_samples:
            return True  # Always explore when we don't have enough data
        
        # Epsilon-greedy exploration
        return random.random() < self.EXPLORATION_RATE
    
    def suggest_next_action(self,
                           current_state: Dict[str, Any],
                           available_actions: List[str]) -> str:
        """
        Suggest the next action based on learned patterns.
        
        Args:
            current_state: Current state information
            available_actions: List of available actions
            
        Returns:
            Suggested action
        """
        if self.should_explore():
            return random.choice(available_actions)
        
        # Exploit: choose best action based on Q-values
        state_key = self._get_state_key(current_state)
        q_values = self.q_table.get(state_key, {})
        
        if not q_values:
            return random.choice(available_actions)
        
        # Filter to available actions
        valid_q = {a: q_values.get(a, 0) for a in available_actions}
        
        return max(valid_q.items(), key=lambda x: x[1])[0]
    
    def get_learning_stats(self) -> Dict[str, Any]:
        """Get statistics about the learning system."""
        avg_rewards = {
            attack: sum(rewards) / len(rewards) if rewards else 0
            for attack, rewards in self.reward_history.items()
        }
        
        return {
            'training_samples': self.state.training_samples,
            'patterns_learned': len(self.state.patterns),
            'attack_weights': self.state.attack_weights,
            'average_rewards': avg_rewards,
            'q_table_states': len(self.q_table),
            'last_update': self.state.last_update.isoformat() if self.state.last_update else None,
            'ready': self.state.training_samples >= self.min_samples
        }
    
    def _learn_attack_preferences(self, session: SandboxSession):
        """Learn attack type preferences from a session."""
        attack_sequence = session.get_attack_sequence()
        
        for attack in attack_sequence:
            attack_lower = attack.lower()
            self.state.attack_weights[attack_lower] = \
                self.state.attack_weights.get(attack_lower, 0) + 1
    
    def _learn_payload_preferences(self, session: SandboxSession):
        """Learn payload preferences from a session."""
        payload_actions = session.get_actions_by_type(ActionType.PAYLOAD_INJECTED)
        custom_actions = session.get_actions_by_type(ActionType.CUSTOM_PAYLOAD_ADDED)
        
        # Track payload success rates
        payload_success: Dict[str, Dict[str, int]] = defaultdict(lambda: {'success': 0, 'total': 0})
        
        for action in payload_actions:
            payload = action.data.get('payload', '')
            success = action.data.get('success', False)
            attack_type = self._detect_payload_type(payload)
            
            key = f"{attack_type}:{payload[:50]}"
            payload_success[key]['total'] += 1
            if success:
                payload_success[key]['success'] += 1
        
        # Update payload rankings based on success rates
        attack_payloads: Dict[str, List[Tuple[str, float]]] = defaultdict(list)
        
        for key, stats in payload_success.items():
            attack_type, payload = key.split(':', 1)
            success_rate = stats['success'] / stats['total'] if stats['total'] > 0 else 0
            attack_payloads[attack_type].append((payload, success_rate))
        
        # Sort by success rate and update rankings
        for attack_type, payloads in attack_payloads.items():
            sorted_payloads = sorted(payloads, key=lambda x: x[1], reverse=True)
            self.state.payload_rankings[attack_type] = [p[0] for p in sorted_payloads]
        
        # Add custom payloads to rankings (high priority)
        for action in custom_actions:
            payload = action.data.get('payload', '')
            attack_type = action.data.get('attack_type', 'unknown')
            
            if attack_type in self.state.payload_rankings:
                if payload not in self.state.payload_rankings[attack_type]:
                    self.state.payload_rankings[attack_type].insert(0, payload)
            else:
                self.state.payload_rankings[attack_type] = [payload]
    
    def _learn_workflow_patterns(self, session: SandboxSession):
        """Learn workflow patterns from a session."""
        # Analyze action sequences
        actions = session.actions
        
        # Track common action pairs
        for i in range(len(actions) - 1):
            current = actions[i].action_type.value
            next_action = actions[i + 1].action_type.value
            
            pair_key = f"{current}->{next_action}"
            self.state.workflow_preferences[pair_key] = \
                self.state.workflow_preferences.get(pair_key, 0) + 1
    
    def _update_q_values(self, session: SandboxSession):
        """Update Q-values based on session outcomes."""
        # Get successful attacks
        attack_starts = session.get_actions_by_type(ActionType.ATTACK_INITIATED)
        attack_completes = session.get_actions_by_type(ActionType.ATTACK_COMPLETED)
        findings_confirmed = session.get_actions_by_type(ActionType.FINDING_CONFIRMED)
        
        # Map attacks to outcomes
        for complete_action in attack_completes:
            attack_type = complete_action.data.get('attack_type', 'unknown')
            findings_count = complete_action.data.get('findings_count', 0)
            
            # Derive target features from session context
            target_features = {
                'has_forms': True,  # Default assumption
                'has_params': True,
                'target_type': 'web'
            }
            
            # Calculate reward based on findings
            success = findings_count > 0
            severity_score = findings_count * 2  # Simple estimation
            
            self.record_reward(
                attack_type=attack_type.lower(),
                target_features=target_features,
                success=success,
                finding_count=findings_count,
                severity_score=severity_score
            )
    
    def _get_state_key(self, features: Dict[str, Any]) -> str:
        """Convert features to a state key for Q-table lookup."""
        has_forms = 'F' if features.get('has_forms') else 'f'
        has_params = 'P' if features.get('has_params') else 'p'
        target_type = features.get('target_type', 'web')[:3]
        
        return f"{target_type}:{has_forms}{has_params}"
    
    def _detect_payload_type(self, payload: str) -> str:
        """Detect the attack type of a payload."""
        payload_lower = payload.lower()
        
        if '<script' in payload_lower or 'onerror' in payload_lower or 'alert(' in payload_lower:
            return 'xss'
        elif 'select' in payload_lower or 'union' in payload_lower or 'or 1=1' in payload_lower:
            return 'sqli'
        elif '../' in payload or '%2e%2e' in payload_lower:
            return 'lfi'
        else:
            return 'other'
    
    def _save_model(self):
        """Save the learned model to disk."""
        try:
            model_file = self.model_path / "model.json"
            
            data = {
                'state': self.state.to_dict(),
                'q_table': dict(self.q_table),
                'reward_history': dict(self.reward_history),
                'saved_at': datetime.now().isoformat()
            }
            
            with open(model_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Saved learning model to {model_file}")
            
        except Exception as e:
            logger.error(f"Failed to save model: {e}")
    
    def _load_model(self):
        """Load existing model from disk."""
        try:
            model_file = self.model_path / "model.json"
            
            if not model_file.exists():
                return
            
            with open(model_file, 'r') as f:
                data = json.load(f)
            
            # Restore state
            state_data = data.get('state', {})
            self.state.attack_weights = state_data.get('attack_weights', {})
            self.state.payload_rankings = state_data.get('payload_rankings', {})
            self.state.workflow_preferences = state_data.get('workflow_preferences', {})
            self.state.training_samples = state_data.get('training_samples', 0)
            
            if state_data.get('last_update'):
                self.state.last_update = datetime.fromisoformat(state_data['last_update'])
            
            # Restore Q-table
            q_data = data.get('q_table', {})
            for state, actions in q_data.items():
                for action, value in actions.items():
                    self.q_table[state][action] = value
            
            # Restore reward history
            self.reward_history = defaultdict(list, data.get('reward_history', {}))
            
            logger.info(f"Loaded learning model with {self.state.training_samples} samples")
            
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
    
    def reset(self):
        """Reset all learned data."""
        self.state = LearningState()
        self.q_table.clear()
        self.reward_history.clear()
        
        # Remove saved model
        model_file = self.model_path / "model.json"
        if model_file.exists():
            model_file.unlink()
        
        logger.info("Reset behavior learner")
