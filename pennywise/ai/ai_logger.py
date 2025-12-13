"""
AI Logging System for PennyWise.
Tracks all AI-related activities, decisions, and learning data.
"""

import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field, asdict
from enum import Enum

logger = logging.getLogger(__name__)


class AILogEvent(Enum):
    """Types of AI logging events."""
    ATTACK_RECOMMENDATION = "attack_recommendation"
    SEVERITY_CLASSIFICATION = "severity_classification"
    PATTERN_ANALYSIS = "pattern_analysis"
    RL_LEARNING = "rl_learning"
    RL_DECISION = "rl_decision"
    MODEL_INFERENCE = "model_inference"
    CONFIDENCE_UPDATE = "confidence_update"


@dataclass
class AttackRecommendationLog:
    """Log entry for attack recommendations."""
    timestamp: str
    target_url: str
    recommended_attacks: List[Dict[str, Any]]
    analysis_confidence: float
    detected_technologies: List[str]
    pattern_matches: Dict[str, int]
    reasoning: str


@dataclass
class SeverityClassificationLog:
    """Log entry for severity classifications."""
    timestamp: str
    finding_id: str
    attack_type: str
    original_severity: str
    ai_classified_severity: str
    confidence_score: float
    ai_reasoning: str
    model_response: str
    classification_time_ms: float


@dataclass
class RLDecisionLog:
    """Log entry for RL decisions."""
    timestamp: str
    episode: int
    state: Dict[str, Any]
    chosen_action: str
    action_confidence: float
    q_values: Dict[str, float]
    reward_received: float
    exploration_used: bool
    user_focus_areas: List[str]


@dataclass
class RLTrainingLog:
    """Log entry for RL training sessions."""
    timestamp: str
    episode: int
    total_episodes: int
    success_rate: float
    average_reward: float
    loss_value: float
    learning_rate: float
    epsilon_value: float
    trajectory_buffer_size: int
    user_embeddings_tracked: int
    training_duration_ms: float


@dataclass
class ModelInferenceLog:
    """Log entry for AI model inferences."""
    timestamp: str
    model_name: str
    input_tokens: int
    output_tokens: int
    inference_time_ms: float
    gpu_memory_used_mb: float
    confidence_score: float
    prompt_type: str
    response_quality: str


class AILogger:
    """
    Comprehensive AI logging system for PennyWise.

    Tracks all AI activities including:
    - Attack recommendations
    - Severity classifications
    - RL learning decisions
    - Model inference metrics
    - Pattern analysis results
    """

    def __init__(self, log_file: str = "ai_log.json"):
        self.log_file = Path(log_file)
        self.logs: Dict[str, List[Dict[str, Any]]] = {
            "attack_recommendations": [],
            "severity_classifications": [],
            "rl_decisions": [],
            "rl_training": [],
            "model_inferences": [],
            "pattern_analysis": []
        }
        self._load_existing_logs()

    def _load_existing_logs(self):
        """Load existing logs from file."""
        if self.log_file.exists():
            try:
                with open(self.log_file, 'r') as f:
                    data = json.load(f)
                    self.logs.update(data)
                logger.info(f"Loaded {sum(len(v) for v in self.logs.values())} existing AI log entries")
            except Exception as e:
                logger.warning(f"Failed to load existing AI logs: {e}")

    def _save_logs(self):
        """Save logs to file."""
        try:
            with open(self.log_file, 'w') as f:
                json.dump(self.logs, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Failed to save AI logs: {e}")

    def log_attack_recommendation(self,
                                  target_url: str,
                                  recommended_attacks: List[Dict[str, Any]],
                                  analysis_confidence: float,
                                  detected_technologies: List[str],
                                  pattern_matches: Dict[str, int],
                                  reasoning: str):
        """Log attack recommendation analysis."""
        log_entry = AttackRecommendationLog(
            timestamp=datetime.now().isoformat(),
            target_url=target_url,
            recommended_attacks=recommended_attacks,
            analysis_confidence=analysis_confidence,
            detected_technologies=detected_technologies,
            pattern_matches=pattern_matches,
            reasoning=reasoning
        )

        self.logs["attack_recommendations"].append(asdict(log_entry))
        self._save_logs()

        logger.info(f"AI Log: Attack recommendation for {target_url} - {len(recommended_attacks)} attacks recommended")

    def log_severity_classification(self,
                                    finding_id: str,
                                    attack_type: str,
                                    original_severity: str,
                                    ai_classified_severity: str,
                                    confidence_score: float,
                                    ai_reasoning: str,
                                    model_response: str,
                                    classification_time_ms: float):
        """Log severity classification."""
        log_entry = SeverityClassificationLog(
            timestamp=datetime.now().isoformat(),
            finding_id=finding_id,
            attack_type=attack_type,
            original_severity=original_severity,
            ai_classified_severity=ai_classified_severity,
            confidence_score=confidence_score,
            ai_reasoning=ai_reasoning,
            model_response=model_response,
            classification_time_ms=classification_time_ms
        )

        self.logs["severity_classifications"].append(asdict(log_entry))
        self._save_logs()

        logger.info(f"AI Log: Severity classification for {finding_id} - {original_severity} → {ai_classified_severity} (confidence: {confidence_score:.2f})")

    def log_rl_decision(self,
                        episode: int,
                        state: Dict[str, Any],
                        chosen_action: str,
                        action_confidence: float,
                        q_values: Dict[str, float],
                        reward_received: float,
                        exploration_used: bool,
                        user_focus_areas: List[str]):
        """Log RL decision making."""
        log_entry = RLDecisionLog(
            timestamp=datetime.now().isoformat(),
            episode=episode,
            state=state,
            chosen_action=chosen_action,
            action_confidence=action_confidence,
            q_values=q_values,
            reward_received=reward_received,
            exploration_used=exploration_used,
            user_focus_areas=user_focus_areas
        )

        self.logs["rl_decisions"].append(asdict(log_entry))
        self._save_logs()

        logger.debug(f"AI Log: RL Decision episode {episode} - {chosen_action} (reward: {reward_received:.3f})")

    def log_rl_training(self,
                        episode: int,
                        total_episodes: int,
                        success_rate: float,
                        average_reward: float,
                        loss_value: float,
                        learning_rate: float,
                        epsilon_value: float,
                        trajectory_buffer_size: int,
                        user_embeddings_tracked: int,
                        training_duration_ms: float):
        """Log RL training session."""
        log_entry = RLTrainingLog(
            timestamp=datetime.now().isoformat(),
            episode=episode,
            total_episodes=total_episodes,
            success_rate=success_rate,
            average_reward=average_reward,
            loss_value=loss_value,
            learning_rate=learning_rate,
            epsilon_value=epsilon_value,
            trajectory_buffer_size=trajectory_buffer_size,
            user_embeddings_tracked=user_embeddings_tracked,
            training_duration_ms=training_duration_ms
        )

        self.logs["rl_training"].append(asdict(log_entry))
        self._save_logs()

        logger.info(f"AI Log: RL Training episode {episode}/{total_episodes} - Success: {success_rate:.1%}, Avg Reward: {average_reward:.3f}")

    def log_model_inference(self,
                            model_name: str,
                            input_tokens: int,
                            output_tokens: int,
                            inference_time_ms: float,
                            gpu_memory_used_mb: float,
                            confidence_score: float,
                            prompt_type: str,
                            response_quality: str):
        """Log AI model inference."""
        log_entry = ModelInferenceLog(
            timestamp=datetime.now().isoformat(),
            model_name=model_name,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            inference_time_ms=inference_time_ms,
            gpu_memory_used_mb=gpu_memory_used_mb,
            confidence_score=confidence_score,
            prompt_type=prompt_type,
            response_quality=response_quality
        )

        self.logs["model_inferences"].append(asdict(log_entry))
        self._save_logs()

        logger.debug(f"AI Log: Model inference {model_name} - {inference_time_ms:.1f}ms, confidence: {confidence_score:.2f}")

    def log_pattern_analysis(self,
                             target_url: str,
                             patterns_found: Dict[str, List[str]],
                             vulnerability_scores: Dict[str, float],
                             analysis_time_ms: float):
        """Log pattern analysis results."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "target_url": target_url,
            "patterns_found": patterns_found,
            "vulnerability_scores": vulnerability_scores,
            "analysis_time_ms": analysis_time_ms
        }

        self.logs["pattern_analysis"].append(log_entry)
        self._save_logs()

        logger.info(f"AI Log: Pattern analysis for {target_url} - {len(patterns_found)} pattern types found")

    def get_logs_summary(self) -> Dict[str, Any]:
        """Get summary of all logged activities."""
        return {
            "total_attack_recommendations": len(self.logs["attack_recommendations"]),
            "total_severity_classifications": len(self.logs["severity_classifications"]),
            "total_rl_decisions": len(self.logs["rl_decisions"]),
            "total_rl_training_sessions": len(self.logs["rl_training"]),
            "total_model_inferences": len(self.logs["model_inferences"]),
            "total_pattern_analyses": len(self.logs["pattern_analysis"]),
            "last_activity": max(
                [entry.get("timestamp", "2000-01-01") for log_list in self.logs.values() for entry in log_list],
                default=None
            )
        }

    def export_logs(self, output_file: str):
        """Export all logs to a file."""
        export_data = {
            "export_timestamp": datetime.now().isoformat(),
            "summary": self.get_logs_summary(),
            "logs": self.logs
        }

        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)

        logger.info(f"AI logs exported to {output_file}")


# Global AI logger instance
_ai_logger = None

def get_ai_logger(log_file: str = "ai_log.json") -> AILogger:
    """Get the global AI logger instance."""
    global _ai_logger
    if _ai_logger is None:
        _ai_logger = AILogger(log_file)
    return _ai_logger