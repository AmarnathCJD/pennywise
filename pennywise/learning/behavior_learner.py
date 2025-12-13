"""
Behavior Learner for PennyWise.
Hierarchical Reinforcement Learning with PPO for adaptive penetration testing.
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
import threading
import time

import torch
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F
from torch.distributions import Categorical

from ..sandbox.environment import SandboxEnvironment, SandboxSession, ActionType
from ..config import AttackType
from ..ai.ai_logger import get_ai_logger

logger = logging.getLogger(__name__)


class UserEmbedding(nn.Module):
    """Learnable user embedding for personalization."""

    def __init__(self, embedding_dim: int = 8):
        super(UserEmbedding, self).__init__()
        self.embedding_dim = embedding_dim
        # Start with random embeddings, will be learned
        self.user_embeddings = nn.Parameter(torch.randn(100, embedding_dim) * 0.1)

    def forward(self, user_id: int) -> torch.Tensor:
        """Get embedding for a user."""
        return self.user_embeddings[user_id % len(self.user_embeddings)]


class HighLevelPolicy(nn.Module):
    """High-level PPO policy for strategy selection."""

    def __init__(self, state_dim: int, user_embedding_dim: int, action_dim: int, hidden_dim: int = 128):
        super(HighLevelPolicy, self).__init__()
        self.state_dim = state_dim
        self.user_embedding_dim = user_embedding_dim
        self.action_dim = action_dim

        # Combine state and user embedding
        combined_dim = state_dim + user_embedding_dim

        self.fc1 = nn.Linear(combined_dim, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, hidden_dim)
        self.fc3 = nn.Linear(hidden_dim, action_dim)

    def forward(self, state: torch.Tensor, user_embedding: torch.Tensor) -> torch.Tensor:
        # Expand user_embedding to match batch size if needed
        if user_embedding.dim() == 1 and state.dim() == 2:
            user_embedding = user_embedding.unsqueeze(0).expand(state.size(0), -1)
        elif user_embedding.dim() == 2 and state.dim() == 2:
            # Ensure batch sizes match
            if user_embedding.size(0) != state.size(0):
                user_embedding = user_embedding.expand(state.size(0), -1)

        x = torch.cat([state, user_embedding], dim=-1)
        x = F.relu(self.fc1(x))
        x = F.relu(self.fc2(x))
        x = self.fc3(x)
        return F.softmax(x, dim=-1)


class LowLevelStrategy(nn.Module):
    """Low-level strategy selector (could be PPO or simple MLP)."""

    def __init__(self, state_dim: int, high_level_action_dim: int, strategy_dim: int, hidden_dim: int = 64):
        super(LowLevelStrategy, self).__init__()
        combined_dim = state_dim + high_level_action_dim

        self.fc1 = nn.Linear(combined_dim, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, hidden_dim)
        self.fc3 = nn.Linear(hidden_dim, strategy_dim)

    def forward(self, state: torch.Tensor, high_level_action: torch.Tensor) -> torch.Tensor:
        x = torch.cat([state, high_level_action], dim=-1)
        x = F.relu(self.fc1(x))
        x = F.relu(self.fc2(x))
        x = self.fc3(x)
        return F.softmax(x, dim=-1)


class ValueNetwork(nn.Module):
    """Value network for PPO."""

    def __init__(self, state_dim: int, user_embedding_dim: int, hidden_dim: int = 128):
        super(ValueNetwork, self).__init__()
        combined_dim = state_dim + user_embedding_dim

        self.fc1 = nn.Linear(combined_dim, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, hidden_dim)
        self.fc3 = nn.Linear(hidden_dim, 1)

    def forward(self, state: torch.Tensor, user_embedding: torch.Tensor) -> torch.Tensor:
        # Expand user_embedding to match batch size if needed
        if user_embedding.dim() == 1 and state.dim() == 2:
            user_embedding = user_embedding.unsqueeze(0).expand(state.size(0), -1)
        elif user_embedding.dim() == 2 and state.dim() == 2:
            # Ensure batch sizes match
            if user_embedding.size(0) != state.size(0):
                user_embedding = user_embedding.expand(state.size(0), -1)

        x = torch.cat([state, user_embedding], dim=-1)
        x = F.relu(self.fc1(x))
        x = F.relu(self.fc2(x))
        x = self.fc3(x)
        return x


@dataclass
class HierarchicalTrajectoryStep:
    """Single step in hierarchical trajectory."""
    state: torch.Tensor
    user_embedding: torch.Tensor
    high_level_action: int
    high_level_log_prob: float
    low_level_action: int
    low_level_log_prob: float
    value: float
    reward: float
    done: bool


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


class PPOAgent:
    """
    Hierarchical PPO Agent for PennyWise.

    High-level: Chooses strategy categories (login_probe, api_probe, etc.)
    Low-level: Chooses payload strategies within categories
    """

    def __init__(self,
                 state_dim: int = 16,
                 user_embedding_dim: int = 8,
                 high_level_actions: int = 6,  # Strategy categories
                 low_level_strategies: int = 4,  # Payload strategies per category
                 hidden_dim: int = 128,
                 lr: float = 3e-4,
                 gamma: float = 0.99,
                 gae_lambda: float = 0.95,
                 clip_ratio: float = 0.2,
                 epochs: int = 10,
                 batch_size: int = 64,
                 max_grad_norm: float = 0.5):
        """
        Initialize hierarchical PPO agent.

        Args:
            state_dim: Dimension of state space
            user_embedding_dim: User embedding dimension
            high_level_actions: Number of high-level strategy categories
            low_level_strategies: Number of low-level payload strategies
            hidden_dim: Hidden layer dimension
            lr: Learning rate
            gamma: Discount factor
            gae_lambda: GAE lambda parameter
            clip_ratio: PPO clipping ratio
            epochs: Number of PPO epochs per update
            batch_size: Batch size for updates
            max_grad_norm: Maximum gradient norm for clipping
        """
        self.state_dim = state_dim
        self.user_embedding_dim = user_embedding_dim
        self.high_level_actions = high_level_actions
        self.low_level_strategies = low_level_strategies
        self.gamma = gamma
        self.gae_lambda = gae_lambda
        self.clip_ratio = clip_ratio
        self.epochs = epochs
        self.batch_size = batch_size
        self.max_grad_norm = max_grad_norm

        # Neural networks
        self.high_level_policy = HighLevelPolicy(state_dim, user_embedding_dim, high_level_actions, hidden_dim)
        self.low_level_strategy = LowLevelStrategy(state_dim, high_level_actions, low_level_strategies, hidden_dim // 2)
        self.value_net = ValueNetwork(state_dim, user_embedding_dim, hidden_dim)
        self.user_embedding = UserEmbedding(user_embedding_dim)

        # Optimizers
        self.policy_optimizer = optim.Adam([
            {'params': self.high_level_policy.parameters()},
            {'params': self.low_level_strategy.parameters()},
            {'params': self.user_embedding.parameters()}
        ], lr=lr)
        self.value_optimizer = optim.Adam(self.value_net.parameters(), lr=lr)

        # High-level action mapping (strategy categories)
        self.high_level_mapping = {
            0: 'login_form_probe',      # Focus on login forms
            1: 'api_endpoint_probe',    # API testing
            2: 'auth_flow_probe',       # Authentication flows
            3: 'parameter_probe',       # Parameter-based attacks
            4: 'workflow_variant',      # Try different workflows
            5: 'stop_session'           # End current session
        }

        # Low-level strategy mapping (payload strategies)
        self.low_level_mapping = {
            0: 'mutate_known_pattern',     # Modify known working payloads
            1: 'bruteforce_safe_range',    # Safe bruteforce within limits
            2: 'structured_token_variation', # Vary tokens systematically
            3: 'heuristics_small_mutation'  # Small heuristic changes
        }

        # User pattern learning
        self.user_action_history = defaultdict(list)
        self.user_success_rates = defaultdict(lambda: defaultdict(float))
        self.user_strategy_preferences = defaultdict(lambda: defaultdict(float))
        self.user_focus_areas = set()  # Track what attack types user focuses on

        # Payload success tracking
        self.payload_success_rates = defaultdict(lambda: defaultdict(float))

        # Learning statistics
        self.total_episodes = 0
        self.successful_episodes = 0
        self.trajectory_buffer = []

        # Real-time logging
        self.log_callback = None
        self.ai_logger = get_ai_logger()

        logger.info("🧠 Hierarchical PPO Agent initialized")

    def set_log_callback(self, callback):
        """Set callback for real-time learning logs."""
        self.log_callback = callback

    def _log_learning_event(self, event_type: str, data: Dict[str, Any]):
        """Log a learning event."""
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "data": data
        }

        if self.log_callback:
            self.log_callback(event)

        logger.info(f"🧠 Hierarchical PPO Event: {event_type} - {data}")

    def get_state_tensor(self, target_features: Dict[str, Any], episode_step: int = 0, time_elapsed: float = 0.0) -> torch.Tensor:
        """Convert target features to compact state tensor (16 dimensions)."""
        # Binary/numeric features
        has_forms = float(target_features.get('has_forms', False))
        has_login = float(target_features.get('has_login_form', False) or
                         target_features.get('has_username_field', False))
        num_params = min(target_features.get('num_params', 0) / 10.0, 1.0)  # Normalized
        num_inputs = min(target_features.get('num_inputs', 0) / 5.0, 1.0)   # Normalized

        # Recent success metrics
        last_success_count = min(target_features.get('last_successful_attack_count', 0) / 5.0, 1.0)
        avg_response_time = min(target_features.get('avg_response_time', 1.0) / 5.0, 1.0)

        # Content type (simple encoding)
        content_type = target_features.get('content_type', 'html')
        is_html = 1.0 if 'html' in content_type.lower() else 0.0
        is_json = 1.0 if 'json' in content_type.lower() else 0.0

        # Tech stack (one-hot style)
        tech_stack = target_features.get('technologies', [])
        has_php = 1.0 if any('php' in str(t).lower() for t in tech_stack) else 0.0
        has_node = 1.0 if any('node' in str(t).lower() for t in tech_stack) else 0.0
        has_mysql = 1.0 if any('mysql' in str(t).lower() for t in tech_stack) else 0.0

        # Episode progress
        step_norm = min(episode_step / 10.0, 1.0)  # Normalized step index
        time_norm = min(time_elapsed / 300.0, 1.0)  # Normalized time (5 min max)

        # User pattern features
        user_sqli_focus = float(target_features.get('user_focus_sqli', False))
        user_xss_focus = float(target_features.get('user_focus_xss', False))

        state = [
            has_forms, has_login, num_params, num_inputs,
            last_success_count, avg_response_time,
            is_html, is_json, has_php, has_node, has_mysql,
            step_norm, time_norm, user_sqli_focus, user_xss_focus,
            0.0  # Padding to 16 dims
        ]

        return torch.tensor(state, dtype=torch.float32).unsqueeze(0)

    def choose_action(self, target_features: Dict[str, Any], user_id: int = 0,
                     episode_step: int = 0, time_elapsed: float = 0.0) -> Tuple[int, int, float, float]:
        """
        Choose hierarchical action: (high_level_action, low_level_strategy, high_log_prob, low_log_prob)

        Returns:
            (high_level_action_idx, low_level_strategy_idx, high_log_prob, low_log_prob)
        """
        state = self.get_state_tensor(target_features, episode_step, time_elapsed)
        user_emb = self.user_embedding(user_id)

        with torch.no_grad():
            # High-level action selection
            high_level_probs = self.high_level_policy(state, user_emb)
            high_level_dist = Categorical(high_level_probs)
            high_level_action = high_level_dist.sample()
            high_level_log_prob = high_level_dist.log_prob(high_level_action)

            # Low-level strategy selection (conditioned on high-level)
            high_level_action_scalar = high_level_action.squeeze().item()
            high_level_onehot = F.one_hot(torch.tensor(high_level_action_scalar, dtype=torch.long), num_classes=self.high_level_actions).float().unsqueeze(0)
            low_level_probs = self.low_level_strategy(state, high_level_onehot)
            low_level_dist = Categorical(low_level_probs)
            low_level_action = low_level_dist.sample()
            low_level_log_prob = low_level_dist.log_prob(low_level_action)

        high_action_name = self.high_level_mapping[high_level_action.item()]
        low_action_name = self.low_level_mapping[low_level_action.item()]

        # Log RL decision with AI logger
        self.ai_logger.log_rl_decision(
            episode=self.total_episodes,
            state=target_features,
            chosen_action=f"{high_action_name}:{low_action_name}",
            action_confidence=high_level_probs[0][high_level_action].item(),
            q_values={action: prob.item() for action, prob in enumerate(high_level_probs[0])},
            reward_received=0.0,  # Will be updated when reward is calculated
            exploration_used=random.random() < 0.1,  # Simple epsilon check
            user_focus_areas=list(self.user_focus_areas)
        )

        self._log_learning_event("hierarchical_action_chosen", {
            "high_level": high_action_name,
            "low_level": low_action_name,
            "user_id": user_id,
            "episode_step": episode_step
        })

        return (high_level_action.item(), low_level_action.item(),
                high_level_log_prob.item(), low_level_log_prob.item())

    def store_trajectory_step(self, state: torch.Tensor, user_embedding: torch.Tensor,
                            high_action: int, high_log_prob: float,
                            low_action: int, low_log_prob: float,
                            value: float, reward: float, done: bool):
        """Store a step in the trajectory buffer."""
        step = HierarchicalTrajectoryStep(
            state=state, user_embedding=user_embedding,
            high_level_action=high_action, high_level_log_prob=high_log_prob,
            low_level_action=low_action, low_level_log_prob=low_log_prob,
            value=value, reward=reward, done=done
        )
        self.trajectory_buffer.append(step)

    def calculate_advantages(self, trajectory: List[HierarchicalTrajectoryStep]) -> List[float]:
        """Calculate Generalized Advantage Estimation (GAE)."""
        advantages = []
        gae = 0

        for i in reversed(range(len(trajectory))):
            if i == len(trajectory) - 1:
                next_value = 0  # Terminal state
            else:
                next_value = trajectory[i + 1].value

            delta = trajectory[i].reward + self.gamma * next_value - trajectory[i].value
            gae = delta + self.gamma * self.gae_lambda * gae
            advantages.insert(0, gae)

        return advantages

    def update_policy(self):
        """Update hierarchical policy and value networks using PPO."""
        if len(self.trajectory_buffer) < self.batch_size:
            return

        # Convert trajectory to tensors
        states = torch.stack([step.state for step in self.trajectory_buffer])
        user_embeddings = torch.stack([step.user_embedding for step in self.trajectory_buffer])
        high_actions = torch.tensor([step.high_level_action for step in self.trajectory_buffer])
        high_log_probs = torch.tensor([step.high_level_log_prob for step in self.trajectory_buffer])
        low_actions = torch.tensor([step.low_level_action for step in self.trajectory_buffer])
        low_log_probs = torch.tensor([step.low_level_log_prob for step in self.trajectory_buffer])
        values = torch.tensor([step.value for step in self.trajectory_buffer])
        rewards = torch.tensor([step.reward for step in self.trajectory_buffer])

        # Calculate advantages
        advantages = torch.tensor(self.calculate_advantages(self.trajectory_buffer))
        advantages = (advantages - advantages.mean()) / (advantages.std() + 1e-8)

        # Calculate returns
        returns = advantages + values

        # PPO update for multiple epochs
        for _ in range(self.epochs):
            # High-level policy update
            high_level_probs = self.high_level_policy(states, user_embeddings)
            high_level_dist = Categorical(high_level_probs)
            new_high_log_probs = high_level_dist.log_prob(high_actions)

            # Low-level strategy update
            high_level_onehot = F.one_hot(high_actions, num_classes=self.high_level_actions).float()
            low_level_probs = self.low_level_strategy(states, high_level_onehot)
            low_level_dist = Categorical(low_level_probs)
            new_low_log_probs = low_level_dist.log_prob(low_actions)

            # Combined policy loss
            high_ratio = torch.exp(new_high_log_probs - high_log_probs)
            low_ratio = torch.exp(new_low_log_probs - low_log_probs)

            high_surr1 = high_ratio * advantages
            high_surr2 = torch.clamp(high_ratio, 1 - self.clip_ratio, 1 + self.clip_ratio) * advantages
            low_surr1 = low_ratio * advantages
            low_surr2 = torch.clamp(low_ratio, 1 - self.clip_ratio, 1 + self.clip_ratio) * advantages

            policy_loss = -torch.min(high_surr1, high_surr2).mean() - torch.min(low_surr1, low_surr2).mean()

            # Value loss
            new_values = self.value_net(states, user_embeddings).squeeze()
            value_loss = F.mse_loss(new_values, returns)

            # Total loss
            entropy = high_level_dist.entropy().mean() + low_level_dist.entropy().mean()
            loss = policy_loss + 0.5 * value_loss - 0.01 * entropy

            # Update policy networks
            self.policy_optimizer.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(list(self.high_level_policy.parameters()) +
                                         list(self.low_level_strategy.parameters()) +
                                         list(self.user_embedding.parameters()), self.max_grad_norm)
            self.policy_optimizer.step()

            # Update value network
            self.value_optimizer.zero_grad()
            value_loss.backward()
            torch.nn.utils.clip_grad_norm_(self.value_net.parameters(), self.max_grad_norm)
            self.value_optimizer.step()

        self._log_learning_event("hierarchical_policy_updated", {
            "trajectory_length": len(self.trajectory_buffer),
            "policy_loss": policy_loss.item(),
            "value_loss": value_loss.item(),
            "entropy": entropy.item()
        })

        # Clear buffer
        self.trajectory_buffer.clear()

    def calculate_reward(self, success: bool, findings_count: int, duration: float,
                        requests_made: int, target_features: Dict[str, Any],
                        behavioral_signals: Dict[str, Any] = None) -> float:
        """
        Calculate detailed reward based on multiple factors.

        Args:
            success: Whether attack was successful
            findings_count: Number of findings discovered
            duration: Time taken
            requests_made: Number of requests made
            target_features: Target features
            behavioral_signals: Additional signals like response changes
        """
        reward = 0.0

        # Positive rewards for findings
        if success:
            reward += 1.0  # Base success reward
            reward += findings_count * 0.5  # Bonus per finding

            # Extra bonus for login-focused successes
            if target_features.get('has_login_form', False):
                reward += 0.5

        # Intermediate rewards for behavioral signals
        if behavioral_signals:
            if behavioral_signals.get('response_changed', False):
                reward += 0.1
            if behavioral_signals.get('input_echoed', False):
                reward += 0.1
            if behavioral_signals.get('error_triggered', False):
                reward += 0.05

        # Penalties for inefficiency
        time_penalty = min(duration / 300.0, 1.0) * 0.5  # Max 0.5 penalty for 5+ min
        request_penalty = min(requests_made / 1000.0, 1.0) * 0.3  # Max 0.3 penalty for 1000+ requests

        reward -= time_penalty
        reward -= request_penalty

        # Penalty for repeated futile attempts (would need tracking)
        # This is a simplified version
        if not success and duration > 60:
            reward -= 0.1

        # Clip reward to stable range
        reward = max(-5.0, min(5.0, reward))

        return reward

    def learn_from_episode(self, target_features: Dict[str, Any], user_id: int,
                          high_action: int, low_action: int, success: bool,
                          findings_count: int, duration: float, requests_made: int,
                          behavioral_signals: Dict[str, Any] = None):
        """Learn from a completed episode."""
        self.total_episodes += 1
        if success:
            self.successful_episodes += 1

        # Get state and value
        state = self.get_state_tensor(target_features)
        user_emb = self.user_embedding(user_id)

        with torch.no_grad():
            value = self.value_net(state, user_emb).item()

        # Calculate reward
        reward = self.calculate_reward(success, findings_count, duration, requests_made,
                                     target_features, behavioral_signals)

        # Get log probabilities (would be stored during action selection)
        # For now, approximate - in real implementation, these would be stored
        high_log_prob = 0.0  # Placeholder
        low_log_prob = 0.0   # Placeholder

        # Store trajectory step
        self.store_trajectory_step(state.squeeze(0), user_emb.squeeze(0),
                                high_action, high_log_prob, low_action, low_log_prob,
                                value, reward, True)

        # Update user patterns
        self.update_user_patterns(user_id, high_action, low_action, success)

        # Update policy if buffer is full
        if len(self.trajectory_buffer) >= self.batch_size:
            self.update_policy()

    def update_user_patterns(self, user_id: int, high_action: int, low_action: int, success: bool):
        """Update user pattern learning."""
        # Track action preferences
        self.user_action_history[user_id].append((high_action, low_action))

        # Update success rates
        key = f"{high_action}_{low_action}"
        current_rate = self.user_success_rates[user_id][key]
        # Simple exponential moving average
        self.user_success_rates[user_id][key] = 0.9 * current_rate + 0.1 * float(success)

        # Update strategy preferences
        self.user_strategy_preferences[user_id][high_action] += 0.1 if success else -0.01

    def get_attack_recommendation(self, target_features: Dict[str, Any], user_id: int = 0) -> str:
        """Get attack recommendation based on hierarchical policy."""
        high_action, low_action, _, _ = self.choose_action(target_features, user_id)

        # Map to concrete attack types based on high-level strategy
        strategy_to_attacks = {
            'login_form_probe': ['sqli', 'xss'],
            'api_endpoint_probe': ['sqli', 'csrf'],
            'auth_flow_probe': ['csrf', 'idor'],
            'parameter_probe': ['sqli', 'lfi'],
            'workflow_variant': ['xss', 'rce'],
            'stop_session': ['skip']
        }

        possible_attacks = strategy_to_attacks.get(
            self.high_level_mapping[high_action], ['skip']
        )

        # Return first attack (could be more sophisticated)
        return possible_attacks[0] if possible_attacks else 'skip'

    def get_learning_stats(self) -> Dict[str, Any]:
        """Get comprehensive learning statistics."""
        success_rate = self.successful_episodes / max(1, self.total_episodes)

        return {
            "total_episodes": self.total_episodes,
            "successful_episodes": self.successful_episodes,
            "success_rate": round(success_rate, 3),
            "trajectory_buffer_size": len(self.trajectory_buffer),
            "high_level_actions": self.high_level_actions,
            "low_level_strategies": self.low_level_strategies,
            "user_embeddings_tracked": len(self.user_action_history),
            "policy_params": (sum(p.numel() for p in self.high_level_policy.parameters()) +
                            sum(p.numel() for p in self.low_level_strategy.parameters())),
            "value_params": sum(p.numel() for p in self.value_net.parameters())
        }

    def save_model(self, path: str):
        """Save the hierarchical PPO model."""
        torch.save({
            'high_level_policy': self.high_level_policy.state_dict(),
            'low_level_strategy': self.low_level_strategy.state_dict(),
            'value_net': self.value_net.state_dict(),
            'user_embedding': self.user_embedding.state_dict(),
            'policy_optimizer': self.policy_optimizer.state_dict(),
            'value_optimizer': self.value_optimizer.state_dict(),
            'user_patterns': {
                'action_history': dict(self.user_action_history),
                'success_rates': dict(self.user_success_rates),
                'strategy_preferences': dict(self.user_strategy_preferences)
            },
            'stats': self.get_learning_stats()
        }, path)

    def load_model(self, path: str):
        """Load the hierarchical PPO model."""
        if not Path(path).exists():
            return

        checkpoint = torch.load(path)
        self.high_level_policy.load_state_dict(checkpoint['high_level_policy'])
        self.low_level_strategy.load_state_dict(checkpoint['low_level_strategy'])
        self.value_net.load_state_dict(checkpoint['value_net'])
        self.user_embedding.load_state_dict(checkpoint['user_embedding'])
        self.policy_optimizer.load_state_dict(checkpoint['policy_optimizer'])
        self.value_optimizer.load_state_dict(checkpoint['value_optimizer'])

        # Load user patterns
        patterns = checkpoint.get('user_patterns', {})
        self.user_action_history = defaultdict(list, patterns.get('action_history', {}))
        self.user_success_rates = defaultdict(lambda: defaultdict(float),
                                           patterns.get('success_rates', {}))
        self.user_strategy_preferences = defaultdict(lambda: defaultdict(float),
                                                  patterns.get('strategy_preferences', {}))


class ReinforcementLearner:
    """
    Legacy Q-Learning wrapper for backward compatibility.
    Now delegates to PPO agent.
    """

    def __init__(self, alpha: float = 0.1, gamma: float = 0.9, epsilon: float = 0.2):
        self.ppo_agent = PPOAgent()
        # Keep legacy interface
        self.alpha = alpha
        self.gamma = gamma
        self.epsilon = epsilon

    def set_log_callback(self, callback):
        self.ppo_agent.set_log_callback(callback)

    def get_state_key(self, target_features: Dict[str, Any]) -> str:
        # Legacy method, not used in PPO
        return "ppo_state"

    def choose_action(self, state: str, available_actions: List[str]) -> str:
        # Convert to new interface
        target_features = {'legacy_state': state}
        action_idx, _ = self.ppo_agent.choose_action(target_features)
        return self.ppo_agent.action_mapping[action_idx]

    def learn(self, state: str, action: str, reward: float, next_state: str, done: bool = False):
        # Convert to PPO learning
        target_features = {'legacy_state': state}
        success = reward > 0
        findings_count = int(reward * 2) if success else 0
        self.ppo_agent.learn_from_episode(target_features, action, success, findings_count, 30.0)

    def calculate_reward(self, scan_results: Dict[str, Any]) -> float:
        findings = scan_results.get('findings', [])
        duration = scan_results.get('duration', 0)
        requests = scan_results.get('requests_made', 0)

        # Base reward from findings
        finding_reward = len(findings) * 0.1

        # Bonus for critical/high severity findings
        severity_bonus = 0
        for finding in findings:
            severity = getattr(finding, 'severity', 'unknown')
            if hasattr(severity, 'value'):
                severity = severity.value
            severity = str(severity).lower()
            if severity == 'critical':
                severity_bonus += 0.5
            elif severity == 'high':
                severity_bonus += 0.3

        # Penalty for long scans (efficiency)
        duration_penalty = min(duration / 300.0, 0.5)

        # Penalty for too many requests (stealth)
        request_penalty = min(requests / 1000.0, 0.3)

        reward = finding_reward + severity_bonus - duration_penalty - request_penalty
        return reward

    def start_learning_episode(self, target_features: Dict[str, Any]) -> str:
        return "ppo_episode"

    def end_learning_episode(self, final_reward: float, success: bool = False):
        pass  # PPO handles episodes internally

    def get_learning_stats(self) -> Dict[str, Any]:
        return self.ppo_agent.get_learning_stats()

    def get_recommendations(self, state: str, top_k: int = 3) -> List[Tuple[str, float]]:
        # Return dummy recommendations for compatibility
        return [('sqli', 0.6), ('xss', 0.4)]


class BehaviorLearner:
    """
    Enhanced Behavior Learner with PPO for login-focused attacks.

    Learns user patterns and focuses on SQLi/XSS for login pages.
    """

    def __init__(self,
                 model_path: str = "./pennywise_data/learning_model",
                 min_samples: int = 10,  # Lower threshold for faster adaptation
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

        # Initialize PPO agent
        self.ppo_agent = PPOAgent()

        # Initialize AI logger
        self.ai_logger = get_ai_logger()

        # Legacy Q-table for backward compatibility
        self.q_table: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))

        # Reward history for different actions
        self.reward_history: Dict[str, List[float]] = defaultdict(list)

        # Load existing model
        self._load_model()

        logger.info(f"🧠 Behavior Learner initialized with PPO for login attacks")
        logger.info(f"🧠 User patterns: {len(self.state.patterns)} patterns, {self.state.training_samples} samples")

    def set_realtime_logging(self, callback):
        """Enable real-time PPO logging."""
        self.ppo_agent.set_log_callback(callback)

    def start_learning_session(self, target_features: Dict[str, Any]) -> str:
        """Start a PPO learning session."""
        return self.ppo_agent.get_state_tensor(target_features).squeeze(0)

    def learn_from_scan_results(self, session_state: torch.Tensor, scan_results: Dict[str, Any], next_state=None):
        """
        Learn from scan results using PPO.

        Args:
            session_state: Current session state tensor
            scan_results: Scan results dictionary
            next_state: Next state (optional)
        """
        # Extract key metrics
        findings = scan_results.get('findings', [])
        duration = scan_results.get('duration', 30.0)
        requests_made = scan_results.get('requests_made', 100)
        target_features = scan_results.get('target_features', {})

        # Determine success and action taken
        success = len(findings) > 0
        action_taken = scan_results.get('attack_type', 'unknown')
        findings_count = len(findings)

        # For hierarchical PPO, we need to provide high/low actions
        # For now, use default values since we don't have the actual actions
        user_id = 0  # Default user
        high_action = 0  # Default high-level action (login_probe)
        low_action = 0   # Default low-level action (mutate_known_pattern)

        # Learn from this episode
        self.ppo_agent.learn_from_episode(target_features, user_id, high_action, low_action, success, findings_count, duration, requests_made)

        # Log RL training with AI logger
        self.ai_logger.log_rl_training(
            episode=self.ppo_agent.total_episodes,
            total_episodes=self.ppo_agent.total_episodes,
            success_rate=self.ppo_agent.successful_episodes / max(1, self.ppo_agent.total_episodes),
            average_reward=0.0,  # Would need to track this
            loss_value=0.0,  # Would need to track this from PPO updates
            learning_rate=self.ppo_agent.policy_optimizer.param_groups[0]['lr'],
            epsilon_value=0.1,  # Default epsilon
            trajectory_buffer_size=len(self.ppo_agent.trajectory_buffer),
            user_embeddings_tracked=len(self.ppo_agent.user_action_history),
            training_duration_ms=0.0  # Would need to track this
        )

        # Update traditional learning for compatibility
        self._learn_from_scan_metrics(scan_results)

    def get_rl_recommendations(self, target_features: Dict[str, Any]) -> List[Tuple[str, float]]:
        """Get PPO-based recommendations."""
        recommended_action = self.ppo_agent.get_attack_recommendation(target_features)

        # Return as list with confidence
        confidence = 0.8 if recommended_action != 'skip' else 0.2
        return [(recommended_action, confidence)]

    def get_learning_dashboard(self) -> Dict[str, Any]:
        """Get comprehensive learning dashboard data."""
        ppo_stats = self.ppo_agent.get_learning_stats()

        return {
            "ppo_agent": ppo_stats,
            "behavior_patterns": {
                "total_patterns": len(self.state.patterns),
                "attack_weights": self.state.attack_weights,
                "training_samples": self.state.training_samples,
                "user_focus_areas": list(self.ppo_agent.user_focus_areas)
            },
            "payload_success_rates": dict(self.ppo_agent.payload_success_rates),
            "q_table_summary": {
                state: {action: round(q_val, 3) for action, q_val in actions.items()}
                for state, actions in list(self.q_table.items())[:3]  # Show first 3 states
            }
        }

    def _learn_from_scan_metrics(self, scan_results: Dict[str, Any]):
        """Learn from scan metrics using traditional approach."""
        findings = scan_results.get('findings', [])

        # Update attack type preferences
        attack_counts = {}
        for finding in findings:
            attack_type = getattr(finding, 'attack_type', 'unknown')
            if hasattr(attack_type, 'value'):
                attack_type = attack_type.value
            attack_type = str(attack_type)
            attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1

        # Update weights
        for attack_type, count in attack_counts.items():
            if attack_type in self.state.attack_weights:
                self.state.attack_weights[attack_type] += count * 0.1
            else:
                self.state.attack_weights[attack_type] = count * 0.1

        self.state.training_samples += 1
        self.state.last_update = datetime.now()

    def _learn_from_scan_metrics(self, scan_results: Dict[str, Any]):
        """Learn from scan metrics using traditional approach."""
        findings = scan_results.get('findings', [])

        # Update attack type preferences
        attack_counts = {}
        for finding in findings:
            attack_type = getattr(finding, 'attack_type', 'unknown')
            if hasattr(attack_type, 'value'):
                attack_type = attack_type.value
            attack_type = str(attack_type)
            attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1

        # Update weights
        for attack_type, count in attack_counts.items():
            if attack_type in self.state.attack_weights:
                self.state.attack_weights[attack_type] += count * 0.1
            else:
                self.state.attack_weights[attack_type] = count * 0.1

        self.state.training_samples += 1
        self.state.last_update = datetime.now()
    
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
                                  target_features: Dict[str, Any],
                                  available_attacks: List[str] = None) -> List[str]:
        """
        Get attack type recommendations focused on login pages.

        Returns a list of recommended attack types in order of preference.
        """
        if available_attacks is None:
            available_attacks = ['sqli', 'xss', 'csrf', 'skip']

        # Check if target has login form
        has_login = target_features.get('has_login_form', False) or \
                   target_features.get('has_username_field', False) or \
                   target_features.get('has_password_field', False)

        if not has_login:
            # Only recommend if user has shown broad interest
            if self.ppo_agent.user_focus_areas.issubset({'sqli', 'xss'}):
                return ['skip']  # User focuses only on login attacks
            else:
                return ['skip']  # Default to skip non-login targets

        if self.state.training_samples < self.min_samples:
            # Not enough data, return login-focused defaults
            recommendations = ['sqli', 'xss', 'skip']
            return [r for r in recommendations if r in available_attacks]

        # Use PPO recommendation
        ppo_recommendation = self.ppo_agent.get_attack_recommendation(target_features)

        if ppo_recommendation == 'skip':
            return ['skip']
        elif ppo_recommendation in ['sqli', 'xss']:
            # Prioritize PPO recommendation, then others
            result = [ppo_recommendation]
            remaining = [a for a in ['sqli', 'xss', 'skip'] if a != ppo_recommendation and a in available_attacks]
            result.extend(remaining)
            return result
        else:
            # Fallback to login-focused attacks
            return [a for a in ['sqli', 'xss', 'skip'] if a in available_attacks]

    def get_payload_ranking(self, attack_type: str) -> List[str]:
        """
        Get payload ranking based on learned success rates.

        Returns improved payloads for login attacks.
        """
        if attack_type in self.ppo_agent.payload_success_rates:
            # Sort by success rate
            payloads = sorted(
                self.ppo_agent.payload_success_rates[attack_type].items(),
                key=lambda x: x[1],
                reverse=True
            )
            return [payload for payload, _ in payloads]

        # Fallback to traditional rankings
        return self.state.payload_rankings.get(attack_type, [])

    def get_improved_payload(self, attack_type: str, base_payload: str,
                           target_features: Dict[str, Any]) -> str:
        """
        Get an improved payload based on learning and target features.

        Focuses on login page specific improvements.
        """
        return self.ppo_agent.improvise_payload(base_payload, target_features)

    def should_attack_target(self, target_features: Dict[str, Any]) -> bool:
        """
        Determine if target should be attacked based on learning.

        Avoids impenetrable targets and focuses on user preferences.
        """
        # Skip if no login form and user focuses on login attacks
        has_login = target_features.get('has_login_form', False)
        if not has_login and self.ppo_agent.user_focus_areas.issubset({'sqli', 'xss'}):
            return False

        # Skip if target seems heavily protected
        protection_indicators = [
            target_features.get('has_waf', False),
            target_features.get('has_captcha', False),
            target_features.get('rate_limiting', False),
            target_features.get('requires_2fa', False)
        ]

        protection_score = sum(protection_indicators)
        if protection_score >= 2:  # Multiple protections
            return False

        return True
    
    def record_reward(self,
                     attack_type: str,
                     target_features: Dict[str, Any],
                     success: bool,
                     finding_count: int = 0,
                     severity_score: float = 0):
        """
        Record a reward for an attack action using PPO.

        Args:
            attack_type: Attack type used
            target_features: Features of the target
            success: Whether attack was successful
            finding_count: Number of findings discovered
            severity_score: Sum of severity scores
        """
        # Learn from this episode using PPO
        duration = target_features.get('duration', 30.0)
        self.ppo_agent.learn_from_episode(target_features, attack_type, success, finding_count, duration)

        # Also update traditional Q-table for compatibility
        reward = 1.0 if success else -0.1
        state_key = self._get_state_key(target_features)
        current_q = self.q_table[state_key].get(attack_type, 0.0)
        new_q = current_q + 0.1 * (reward - current_q)  # Simple Q-learning update
        self.q_table[state_key][attack_type] = new_q

        # Track reward history
        self.reward_history[attack_type].append(reward)

    def should_explore(self) -> bool:
        """Determine if we should explore - PPO handles this internally."""
        return self.state.training_samples < self.min_samples

    def suggest_next_action(self,
                           current_state: Dict[str, Any],
                           available_actions: List[str]) -> str:
        """
        Suggest the next action using PPO policy.

        Args:
            current_state: Current state information
            available_actions: List of available actions

        Returns:
            Suggested action
        """
        recommendation = self.ppo_agent.get_attack_recommendation(current_state)
        if recommendation in available_actions:
            return recommendation
        return random.choice(available_actions)

    def get_learning_stats(self) -> Dict[str, Any]:
        """Get comprehensive learning statistics."""
        ppo_stats = self.ppo_agent.get_learning_stats()

        avg_rewards = {
            attack: sum(rewards) / len(rewards) if rewards else 0
            for attack, rewards in self.reward_history.items()
        }

        return {
            'ppo_stats': ppo_stats,
            'training_samples': self.state.training_samples,
            'patterns_learned': len(self.state.patterns),
            'attack_weights': self.state.attack_weights,
            'average_rewards': avg_rewards,
            'q_table_states': len(self.q_table),
            'user_focus_areas': list(self.ppo_agent.user_focus_areas),
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
        """Save the learned PPO model and patterns."""
        try:
            model_file = self.model_path / "ppo_model.pt"
            self.ppo_agent.save_model(str(model_file))

            # Save additional state
            state_file = self.model_path / "learning_state.json"
            data = {
                'state': self.state.to_dict(),
                'q_table': dict(self.q_table),
                'reward_history': dict(self.reward_history),
                'saved_at': datetime.now().isoformat()
            }

            with open(state_file, 'w') as f:
                json.dump(data, f, indent=2)

            logger.info(f"Saved PPO model to {model_file}")

        except Exception as e:
            logger.error(f"Failed to save PPO model: {e}")

    def _load_model(self):
        """Load existing PPO model and patterns."""
        try:
            model_file = self.model_path / "ppo_model.pt"
            if model_file.exists():
                self.ppo_agent.load_model(str(model_file))

            state_file = self.model_path / "learning_state.json"
            if state_file.exists():
                with open(state_file, 'r') as f:
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

            logger.info(f"Loaded PPO model with {self.state.training_samples} samples")

        except Exception as e:
            logger.error(f"Failed to load PPO model: {e}")
    
    def reset(self):
        """Reset all learned data including PPO model."""
        self.state = LearningState()
        self.q_table.clear()
        self.reward_history.clear()

        # Reset PPO agent
        self.ppo_agent = PPOAgent()

        # Remove saved models
        ppo_model = self.model_path / "ppo_model.pt"
        state_file = self.model_path / "learning_state.json"
        if ppo_model.exists():
            ppo_model.unlink()
        if state_file.exists():
            state_file.unlink()

        logger.info("Reset behavior learner and PPO model")
    
    def record_scan_results(self, scan_result: Any, attack_types: List[Any]):
        """
        Record scan results for learning.
        
        Args:
            scan_result: ScanResult object with findings
            attack_types: List of attack types that were tested
        """
        try:
            # Create a learning session from scan results
            session_data = {
                'url': scan_result.target_url,
                'findings_count': len(scan_result.findings),
                'attack_types': [at.value if hasattr(at, 'value') else str(at) for at in attack_types],
                'pages_scanned': scan_result.pages_scanned,
                'requests_made': scan_result.requests_made,
                'duration': scan_result.duration_seconds,
                'findings': []
            }
            
            # Extract finding details
            for finding in scan_result.findings:
                session_data['findings'].append({
                    'attack_type': finding.attack_type if isinstance(finding.attack_type, str) else finding.attack_type.value,
                    'severity': finding.severity if isinstance(finding.severity, str) else finding.severity.value,
                    'payload': finding.payload,
                    'url': finding.url
                })
            
            # Learn from this session
            self.learn_from_scan_session(session_data)
            
        except Exception as e:
            logger.debug(f"Failed to record scan results: {e}")
    
    def learn_from_scan_session(self, session_data: Dict[str, Any]):
        """
        Learn patterns from a completed scan session.
        
        Args:
            session_data: Dictionary containing scan session details
        """
        try:
            attack_types = session_data.get('attack_types', [])
            findings = session_data.get('findings', [])
            
            # Learn attack type preferences based on success
            successful_attacks = set()
            for finding in findings:
                attack_type = finding.get('attack_type')
                if attack_type:
                    successful_attacks.add(attack_type)
            
            # Reward successful attack types
            for attack_type in successful_attacks:
                self.record_reward(attack_type, 1.0, {'success': True})
            
            # Penalize unsuccessful attack types (but not too harshly)
            for attack_type in attack_types:
                attack_str = attack_type if isinstance(attack_type, str) else attack_type.value
                if attack_str not in successful_attacks:
                    self.record_reward(attack_str, 0.1, {'success': False})
            
            # Learn payload preferences
            for finding in findings:
                payload = finding.get('payload')
                if payload:
                    self._learn_payload_success(payload, finding.get('attack_type'))
            
            # Update learning stats
            self.state.training_samples += 1
            self._save_model()
            
        except Exception as e:
            logger.debug(f"Failed to learn from scan session: {e}")
    
    def _learn_payload_success(self, payload: str, attack_type: str):
        """Learn that a specific payload was successful."""
        try:
            if attack_type not in self.state.payload_rankings:
                self.state.payload_rankings[attack_type] = []
            
            ranking = self.state.payload_rankings[attack_type]
            if payload not in ranking:
                ranking.insert(0, payload)  # Add to front as most recent success
                # Keep only top payloads
                self.state.payload_rankings[attack_type] = ranking[:20]
                
        except Exception as e:
            logger.debug(f"Failed to learn payload success: {e}")
