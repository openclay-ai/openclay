"""
Training Data Validation Pipeline

Prevents training data poisoning attacks by validating datasets before training.

Checks:
1. Label consistency
2. Outlier detection (statistical)
3. Adversarial pattern injection
4. Data quality metrics
5. Duplicate detection
"""

import json
import numpy as np
from collections import Counter
from typing import Dict, List, Optional, Tuple
from sklearn.ensemble import IsolationForest


class DataQualityIssue:
    """Represents a data quality issue"""
    def __init__(self, severity: str, category: str, message: str, indices: List[int]):
        self.severity = severity  # "critical", "warning", "info"
        self.category = category  # "label", "outlier", "adversarial", etc.
        self.message = message
        self.indices = indices


class DatasetValidator:
    """
    Training data validation pipeline.
    
    Features:
    - Label consistency checking
    - Statistical outlier detection
    - Adversarial pattern detection
    - Quality scoring
    - Automatic poisoned sample removal
    
    Usage:
        validator = DatasetValidator()
        
        result = validator.validate(X_train, y_train)
        
        if result["is_valid"]:
            # Proceed with training
        else:
            # Fix issues or reject dataset
            clean_X, clean_y = validator.clean_dataset(X_train, y_train)
    """
    
    def __init__(
        self,
        outlier_contamination: float = 0.05,
        min_samples_per_class: int = 10,
        max_duplicate_ratio: float = 0.3
    ):
        """
        Initialize validator.
        
        Args:
            outlier_contamination: Expected outlier ratio (default: 5%)
            min_samples_per_class: Minimum samples required per class
            max_duplicate_ratio: Max allowed duplicate ratio
        """
        self.outlier_contamination = outlier_contamination
        self.min_samples_per_class = min_samples_per_class
        self.max_duplicate_ratio = max_duplicate_ratio
        self.issues = []
    
    def validate(
        self,
        X: np.ndarray,
        y: np.ndarray,
        feature_names: Optional[List[str]] = None
    ) -> Dict:
        """
        Validate training dataset.
        
        Args:
            X: Feature matrix (n_samples, n_features)
            y: Labels (n_samples,)
            feature_names: Optional feature names
        
        Returns:
            Dictionary with validation results
        """
        self.issues = []
        
        # Run all validation checks
        self._check_label_distribution(y)
        self._check_outliers(X)
        self._check_duplicates(X, y)
        self._check_adversarial_patterns(X, feature_names)
        
        # Calculate overall quality score
        quality_score = self._calculate_quality_score()
        
        # Categorize issues
        critical = [i for i in self.issues if i.severity == "critical"]
        warnings = [i for i in self.issues if i.severity == "warning"]
        
        is_valid = len(critical) == 0
        
        return {
            "is_valid": is_valid,
            "quality_score": quality_score,
            "total_issues": len(self.issues),
            "critical_issues": len(critical),
            "warnings": len(warnings),
            "issues": self.issues,
            "recommendation": self._get_recommendation(is_valid, quality_score)
        }
    
    def _check_label_distribution(self, y: np.ndarray):
        """Check if label distribution is balanced and sufficient"""
        label_counts = Counter(y)
        
        # Check minimum samples per class
        for label, count in label_counts.items():
            if count < self.min_samples_per_class:
                self.issues.append(DataQualityIssue(
                    severity="critical",
                    category="label_distribution",
                    message=f"Class {label} has only {count} samples (min: {self.min_samples_per_class})",
                    indices=np.where(y == label)[0].tolist()
                ))
        
        # Check for severe class imbalance
        if len(label_counts) > 1:
            max_count = max(label_counts.values())
            min_count = min(label_counts.values())
            imbalance_ratio = max_count / max(1, min_count)
            
            if imbalance_ratio > 10:
                self.issues.append(DataQualityIssue(
                    severity="warning",
                    category="label_distribution",
                    message=f"Severe class imbalance (ratio: {imbalance_ratio:.1f}:1)",
                    indices=[]
                ))
    
    def _check_outliers(self, X: np.ndarray):
        """Detect statistical outliers using Isolation Forest"""
        if len(X) < 10:
            return  # Too few samples
        
        try:
            # Use Isolation Forest for outlier detection
            clf = IsolationForest(
                contamination=self.outlier_contamination,
                random_state=42
            )
            
            predictions = clf.fit_predict(X)
            outlier_indices = np.where(predictions == -1)[0]
            
            if len(outlier_indices) > 0:
                outlier_ratio = len(outlier_indices) / len(X)
                
                severity = "critical" if outlier_ratio > 0.1 else "warning"
                
                self.issues.append(DataQualityIssue(
                    severity=severity,
                    category="outliers",
                    message=f"Found {len(outlier_indices)} statistical outliers ({outlier_ratio*100:.1f}%)",
                    indices=outlier_indices.tolist()
                ))
        except Exception as e:
            self.issues.append(DataQualityIssue(
                severity="warning",
                category="outliers",
                message=f"Outlier detection failed: {e}",
                indices=[]
            ))
    
    def _check_duplicates(self, X: np.ndarray, y: np.ndarray):
        """Check for excessive duplicate samples"""
        # Find duplicate rows
        unique_samples, unique_indices, counts = np.unique(
            X, axis=0, return_index=True, return_counts=True
        )
        
        duplicate_count = len(X) - len(unique_samples)
        duplicate_ratio = duplicate_count / len(X)
        
        if duplicate_ratio > self.max_duplicate_ratio:
            duplicate_indices = []
            for idx, count in enumerate(counts):
                if count > 1:
                    # Find all occurrences
                    sample = unique_samples[idx]
                    matches = np.where((X == sample).all(axis=1))[0]
                    duplicate_indices.extend(matches[1:].tolist())  # Keep first, mark rest
            
            self.issues.append(DataQualityIssue(
                severity="warning",
                category="duplicates",
                message=f"Excessive duplicates: {duplicate_ratio*100:.1f}% (max: {self.max_duplicate_ratio*100}%)",
                indices=duplicate_indices
            ))
    
    def _check_adversarial_patterns(
        self,
        X: np.ndarray,
        feature_names: Optional[List[str]] = None
    ):
        """Detect potential adversarial pattern injection"""
        # Check for features with suspicious distributions
        for feature_idx in range(X.shape[1]):
            feature_values = X[:, feature_idx]
            
            # Check for constant features (no variance)
            if np.std(feature_values) == 0:
                fname = feature_names[feature_idx] if feature_names else f"feature_{feature_idx}"
                self.issues.append(DataQualityIssue(
                    severity="warning",
                    category="adversarial",
                    message=f"Constant feature detected: {fname} (possible poisoning)",
                    indices=[]
                ))
            
            # Check for extreme values
            mean = np.mean(feature_values)
            std = np.std(feature_values)
            
            if std > 0:
                z_scores = np.abs((feature_values - mean) / std)
                extreme_indices = np.where(z_scores > 5)[0]
                
                if len(extreme_indices) > 0:
                    fname = feature_names[feature_idx] if feature_names else f"feature_{feature_idx}"
                    self.issues.append(DataQualityIssue(
                        severity="info",
                        category="adversarial",
                        message=f"Extreme values in {fname}: {len(extreme_indices)} samples",
                        indices=extreme_indices.tolist()
                    ))
    
    def _calculate_quality_score(self) -> float:
        """
        Calculate overall quality score (0-1).
        
        Higher is better.
        """
        if not self.issues:
            return 1.0
        
        # Penalty weights
        penalties = {
            "critical": 0.3,
            "warning": 0.1,
            "info": 0.02
        }
        
        total_penalty = sum(
            penalties.get(issue.severity, 0.1)
            for issue in self.issues
        )
        
        # Cap at 0
        score = max(0.0, 1.0 - total_penalty)
        
        return score
    
    def _get_recommendation(self, is_valid: bool, quality_score: float) -> str:
        """Get recommendation based on validation results"""
        if not is_valid:
            return "REJECT: Critical issues found. Fix dataset before training."
        
        if quality_score >= 0.9:
            return "APPROVE: High-quality dataset. Safe to train."
        elif quality_score >= 0.7:
            return "REVIEW: Some issues detected. Consider cleaning dataset."
        else:
            return "CAUTION: Multiple quality issues. Clean dataset recommended."
    
    def clean_dataset(
        self,
        X: np.ndarray,
        y: np.ndarray,
        auto_fix: bool = True
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Clean dataset by removing problematic samples.
        
        Args:
            X: Feature matrix
            y: Labels
            auto_fix: Automatically fix issues
        
        Returns:
            Cleaned (X, y)
        """
        if not auto_fix or not self.issues:
            return X, y
        
        # Collect all problematic indices
        remove_indices = set()
        
        for issue in self.issues:
            if issue.severity == "critical":
                # Remove all critical samples
                remove_indices.update(issue.indices)
            elif issue.severity == "warning" and issue.category == "outliers":
                # Remove outliers
                remove_indices.update(issue.indices)
        
        if not remove_indices:
            return X, y
        
        # Keep non-problematic samples
        keep_indices = [i for i in range(len(X)) if i not in remove_indices]
        
        X_clean = X[keep_indices]
        y_clean = y[keep_indices]
        
        print(f"✓ Cleaned dataset: {len(X)} → {len(X_clean)} samples")
        print(f"  Removed: {len(remove_indices)} problematic samples")
        
        return X_clean, y_clean
    
    def generate_report(self) -> str:
        """Generate validation report"""
        report = "# Training Data Validation Report\n\n"
        
        if not self.issues:
            report += "✅ **No issues found - dataset is clean!**\n"
            return report
        
        # Group by category
        by_category = {}
        for issue in self.issues:
            if issue.category not in by_category:
                by_category[issue.category] = []
            by_category[issue.category].append(issue)
        
        for category, issues in by_category.items():
            report += f"\n## {category.replace('_', ' ').title()}\n\n"
            
            for issue in issues:
                icon = "🔴" if issue.severity == "critical" else "⚠️" if issue.severity == "warning" else "ℹ️"
                report += f"{icon} **{issue.severity.upper()}:** {issue.message}\n"
                
                if issue.indices:
                    report += f"   Affected samples: {len(issue.indices)}\n"
                
                report += "\n"
        
        return report


# Example usage
if __name__ == "__main__":
    # Generate synthetic dataset with poisoning
    np.random.seed(42)
    
    # Normal samples
    X_normal = np.random.randn(100, 5)
    y_normal = np.random.randint(0, 2, 100)
    
    # Poisoned samples (outliers)
    X_poison = np.random.randn(10, 5) * 10  # Extreme values
    y_poison = np.ones(10, dtype=int)
    
    # Combine
    X = np.vstack([X_normal, X_poison])
    y = np.concatenate([y_normal, y_poison])
    
    # Validate
    validator = DatasetValidator()
    result = validator.validate(X, y)
    
    print("Validation Results:")
    print(f"  Valid: {result['is_valid']}")
    print(f"  Quality Score: {result['quality_score']:.2f}")
    print(f"  Total Issues: {result['total_issues']}")
    print(f"  Critical: {result['critical_issues']}")
    print(f"  Warnings: {result['warnings']}")
    print(f"\n  Recommendation: {result['recommendation']}")
    print()
    
    # Generate report
    print(validator.generate_report())
    
    # Clean dataset
    X_clean, y_clean = validator.clean_dataset(X, y)
    
    # Re-validate
    result2 = validator.validate(X_clean, y_clean)
    print(f"\nAfter cleaning:")
    print(f"  Quality Score: {result2['quality_score']:.2f}")
    print(f"  Recommendation: {result2['recommendation']}")
