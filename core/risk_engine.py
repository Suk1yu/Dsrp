"""
core/risk_engine.py
Combines behavior analysis and ML scores into a unified risk assessment.
"""

from dataclasses import dataclass, field
from typing import Optional


LEVEL_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
}


@dataclass
class RiskAssessment:
    package_name: str
    behavior_score: int = 0
    behavior_level: str = "LOW"
    ml_probability: float = 0.0
    ml_label: str = "BENIGN"
    combined_score: float = 0.0
    final_level: str = "LOW"
    flags: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)
    triggered_rules: list = field(default_factory=list)


ML_THRESHOLDS = {
    "CRITICAL": 0.80,
    "HIGH": 0.60,
    "MEDIUM": 0.35,
    "LOW": 0.0,
}

BEHAVIOR_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 1,
}


class RiskEngine:
    """
    Merges behavioral rule scores and ML probability into
    a combined risk score and classification.
    """

    def __init__(self, ml_weight: float = 0.4, behavior_weight: float = 0.6):
        self.ml_weight = ml_weight
        self.behavior_weight = behavior_weight

    def assess(self,
               profile,
               behavior_report=None,
               ml_probability: float = 0.0) -> RiskAssessment:
        """
        Produce a unified RiskAssessment.
        profile: AppProfile
        behavior_report: BehaviorReport or dict
        ml_probability: float 0.0 - 1.0
        """
        assessment = RiskAssessment(package_name=profile.package_name)

        # Extract behavior data
        if behavior_report is not None:
            if isinstance(behavior_report, dict):
                b_score = behavior_report.get("score", 0)
                b_level = behavior_report.get("level", "LOW")
                assessment.flags = behavior_report.get("flags", [])
                assessment.triggered_rules = behavior_report.get("triggered_rules", [])
            else:
                b_score = behavior_report.score
                b_level = behavior_report.level
                assessment.flags = behavior_report.flags
                assessment.triggered_rules = behavior_report.triggered_rules
        else:
            b_score = 0
            b_level = "LOW"

        assessment.behavior_score = b_score
        assessment.behavior_level = b_level
        assessment.ml_probability = ml_probability

        # ML label
        for level, thresh in ML_THRESHOLDS.items():
            if ml_probability >= thresh:
                assessment.ml_label = level
                break

        # Normalize behavior score (0-30 typical range) to 0-1
        normalized_behavior = min(b_score / 30.0, 1.0)

        # Combined score
        combined = (
            self.behavior_weight * normalized_behavior +
            self.ml_weight * ml_probability
        )
        assessment.combined_score = round(combined, 3)

        # Final level
        if combined >= 0.75 or (b_level == "CRITICAL") or (ml_probability >= 0.80):
            assessment.final_level = "CRITICAL"
        elif combined >= 0.50 or (b_level == "HIGH") or (ml_probability >= 0.60):
            assessment.final_level = "HIGH"
        elif combined >= 0.25 or (b_level == "MEDIUM") or (ml_probability >= 0.35):
            assessment.final_level = "MEDIUM"
        else:
            assessment.final_level = "LOW"

        assessment.recommendations = self._generate_recommendations(assessment)
        return assessment

    def _generate_recommendations(self, assessment: RiskAssessment) -> list[str]:
        recs = []
        if assessment.final_level in ("CRITICAL", "HIGH"):
            recs.append("Consider uninstalling this application immediately.")
        if "SMS Exfiltration" in assessment.flags:
            recs.append("Revoke SMS permissions or remove app — possible SMS spyware.")
        if "Audio Surveillance" in assessment.flags:
            recs.append("Revoke microphone permission — possible covert recording.")
        if "Device Admin Privilege" in assessment.flags:
            recs.append("Revoke device admin rights in Settings > Security.")
        if "APK Install Capability" in assessment.flags:
            recs.append("Revoke INSTALL_PACKAGES permission — dropper risk.")
        if "Full Surveillance Package" in assessment.flags:
            recs.append("This app has all hallmarks of a spyware/stalkerware package.")
        if assessment.final_level == "MEDIUM":
            recs.append("Review permissions granted to this app in Settings.")
        if not recs:
            recs.append("No immediate action required. Monitor periodically.")
        return recs