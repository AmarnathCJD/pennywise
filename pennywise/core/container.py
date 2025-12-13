"""
Dependency Injection Container for PennyWise.
Provides singleton management and component lifecycle.
"""

import logging
from typing import Any, Dict, Optional, Callable
from pathlib import Path

from ..config import PennywiseConfig
from ..ai.model_interface import AIModelInterface
from ..learning.behavior_learner import BehaviorLearner
from ..sandbox.environment import SandboxEnvironment
from .payloads import PayloadLibrary

logger = logging.getLogger(__name__)


class PennywiseContainer:
    """
    Dependency injection container with singleton management.

    Ensures components are created once and reused, preventing
    state leaks and improving performance.
    """

    def __init__(self):
        self._singletons: Dict[str, Any] = {}
        self._factories: Dict[str, Callable] = {}
        self._initialized = False

    def initialize(self, config: PennywiseConfig):
        """Initialize the container with configuration."""
        if self._initialized:
            return

        logger.info("Initializing PennyWise dependency container")

        # Register singletons (expensive to create, reuse)
        self._register_singletons(config)

        # Register factories (created on demand)
        self._register_factories(config)

        self._initialized = True
        logger.info("PennyWise container initialized")

    def _register_singletons(self, config: PennywiseConfig):
        """Register singleton components."""
        # AI Model - load once
        ai_model = AIModelInterface(config.ai.model_path)
        self._singletons['ai_model'] = ai_model

        # Behavior Learner - persistent state
        learner = BehaviorLearner(
            model_path=config.learning.model_path,
            min_samples=50
        )
        self._singletons['learner'] = learner

        # Sandbox Environment - session management
        sandbox = SandboxEnvironment(
            storage_path=config.sandbox.storage_path
        )
        self._singletons['sandbox'] = sandbox

        # Payload Library - dynamic management
        payloads = PayloadLibrary()
        self._singletons['payloads'] = payloads

        # Configuration - immutable
        self._singletons['config'] = config

    def _register_factories(self, config: PennywiseConfig):
        """Register factory functions for on-demand creation."""
        # Scanner factory
        def create_scanner():
            from .enhanced_scanner import EnhancedScanner
            return EnhancedScanner(
                config=self._singletons['config'],
                ai_model=self._singletons['ai_model'],
                learner=self._singletons['learner'],
                payloads=self._singletons['payloads']
            )

        self._factories['scanner'] = create_scanner

        # Target Analyzer factory
        def create_target_analyzer():
            from .target_analyzer import TargetAnalyzer
            return TargetAnalyzer(self._singletons['config'].scan)

        self._factories['target_analyzer'] = create_target_analyzer

        # Attack Selector factory
        def create_attack_selector():
            from .attack_selector import AttackSelector
            return AttackSelector(
                ai_model=self._singletons['ai_model'],
                learner=self._singletons['learner'],
                payloads=self._singletons['payloads'],
                scan_mode=self._singletons['config'].scan.scan_mode
            )

        self._factories['attack_selector'] = create_attack_selector

    def get(self, name: str) -> Any:
        """Get a component instance."""
        if name in self._singletons:
            return self._singletons[name]

        if name in self._factories:
            return self._factories[name]()

        raise ValueError(f"Unknown component: {name}")

    def has_component(self, name: str) -> bool:
        """Check if a component is registered."""
        return name in self._singletons or name in self._factories

    def reset_component(self, name: str):
        """Reset a singleton component (for testing)."""
        if name in self._singletons:
            del self._singletons[name]
            logger.warning(f"Reset singleton component: {name}")

    def get_stats(self) -> Dict[str, Any]:
        """Get container statistics."""
        return {
            'singletons': list(self._singletons.keys()),
            'factories': list(self._factories.keys()),
            'initialized': self._initialized
        }


# Global container instance
_container: Optional[PennywiseContainer] = None


def get_container() -> PennywiseContainer:
    """Get the global container instance."""
    global _container
    if _container is None:
        _container = PennywiseContainer()
    return _container


def initialize_container(config: PennywiseConfig):
    """Initialize the global container."""
    container = get_container()
    container.initialize(config)
    return container