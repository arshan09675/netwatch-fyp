"""
NetWatch Anomaly Detection Module
Methods: Isolation Forest, Z-Score, IQR, Moving Average, LSTM (optional)
"""
import numpy as np
from typing import List, Tuple, Dict, Optional
from collections import deque
from dataclasses import dataclass
import time
import json

# Try to import ML libraries with fallback
try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("[ML] scikit-learn not available, using statistical methods only")

@dataclass
class AnomalyResult:
    is_anomaly: bool
    score: float
    method: str
    severity: str  # low, medium, high
    expected_value: float
    actual_value: float
    message: str

class AdvancedAnomalyDetector:
    """
    Multi-method anomaly detection system
    Combines statistical and ML approaches
    """
    
    def __init__(self, window_size: int = 60, sensitivity: float = 2.0):
        self.window_size = window_size
        self.sensitivity = sensitivity
        self.value_history = deque(maxlen=window_size)
        self.timestamp_history = deque(maxlen=window_size)
        self.model = None
        self._train_model()
    
    def _train_model(self):
        """Train Isolation Forest model when enough data available"""
        if SKLEARN_AVAILABLE and len(self.value_history) > 30:
            data = np.array(self.value_history).reshape(-1, 1)
            self.model = IsolationForest(contamination=0.1, random_state=42)
            self.model.fit(data)
    
    def z_score_detection(self, value: float) -> Tuple[bool, float]:
        """Z-Score method - detects outliers based on standard deviation"""
        if len(self.value_history) < 10:
            return False, 0.0
        
        mean = np.mean(self.value_history)
        std = np.std(self.value_history)
        
        if std == 0:
            return False, 0.0
        
        z_score = abs(value - mean) / std
        is_anomaly = z_score > self.sensitivity
        
        return is_anomaly, z_score
    
    def iqr_detection(self, value: float) -> Tuple[bool, float]:
        """Interquartile Range method - robust to outliers"""
        if len(self.value_history) < 10:
            return False, 0.0
        
        q1 = np.percentile(self.value_history, 25)
        q3 = np.percentile(self.value_history, 75)
        iqr = q3 - q1
        
        lower_bound = q1 - 1.5 * iqr
        upper_bound = q3 + 1.5 * iqr
        
        is_anomaly = value < lower_bound or value > upper_bound
        
        if is_anomaly:
            score = min(abs(value - upper_bound), abs(value - lower_bound)) / iqr if iqr > 0 else 0
        else:
            score = 0
        
        return is_anomaly, score
    
    def moving_average_detection(self, value: float, window: int = 5) -> Tuple[bool, float]:
        """Moving Average with threshold - detects sudden spikes"""
        if len(self.value_history) < window + 1:
            return False, 0.0
        
        recent_values = list(self.value_history)[-window:]
        ma = np.mean(recent_values)
        
        # Dynamic threshold based on recent volatility
        std = np.std(recent_values) if len(recent_values) > 1 else 1
        threshold = ma + (self.sensitivity * std)
        
        is_anomaly = value > threshold
        deviation = (value - ma) / max(ma, 0.1)
        
        return is_anomaly, deviation
    
    def trend_anomaly_detection(self, value: float) -> Tuple[bool, float]:
        """Detect sudden trend changes"""
        if len(self.value_history) < 15:
            return False, 0.0
        
        # Calculate recent trend
        recent = list(self.value_history)[-10:]
        older = list(self.value_history)[-15:-10]
        
        if len(older) < 5:
            return False, 0.0
        
        recent_trend = recent[-1] - recent[0]
        older_trend = older[-1] - older[0]
        
        # If trend direction reverses sharply
        if recent_trend * older_trend < 0 and abs(recent_trend) > abs(older_trend) * 2:
            return True, abs(recent_trend) / max(abs(older_trend), 0.1)
        
        return False, 0.0
    
    def ml_detection(self, value: float) -> Tuple[bool, float]:
        """Isolation Forest ML detection"""
        if self.model is None or len(self.value_history) < 30:
            return False, 0.0
        
        try:
            prediction = self.model.predict([[value]])
            score = self.model.score_samples([[value]])[0]
            is_anomaly = prediction[0] == -1
            return is_anomaly, abs(score)
        except Exception as e:
            print(f"[ML] Detection error: {e}")
            return False, 0.0
    
    def add_value(self, value: float, timestamp: float = None):
        """Add value to history and retrain model periodically"""
        self.value_history.append(value)
        self.timestamp_history.append(timestamp or time.time())
        
        # Retrain model every 100 new values
        if len(self.value_history) % 100 == 0 and len(self.value_history) > 50:
            self._train_model()
    
    def detect(self, value: float, timestamp: float = None) -> AnomalyResult:
        """
        Run all detection methods and return combined result
        """
        self.add_value(value, timestamp)
        
        if len(self.value_history) < 10:
            return AnomalyResult(
                is_anomaly=False,
                score=0,
                method="insufficient_data",
                severity="low",
                expected_value=value,
                actual_value=value,
                message="Insufficient data for anomaly detection"
            )
        
        results = []
        scores = []
        
        # Run all detection methods
        z_anomaly, z_score = self.z_score_detection(value)
        results.append(("z_score", z_anomaly, z_score))
        scores.append(z_score if z_anomaly else 0)
        
        iqr_anomaly, iqr_score = self.iqr_detection(value)
        results.append(("iqr", iqr_anomaly, iqr_score))
        scores.append(iqr_score if iqr_anomaly else 0)
        
        ma_anomaly, ma_score = self.moving_average_detection(value)
        results.append(("moving_average", ma_anomaly, ma_score))
        scores.append(ma_score if ma_anomaly else 0)
        
        trend_anomaly, trend_score = self.trend_anomaly_detection(value)
        results.append(("trend", trend_anomaly, trend_score))
        scores.append(trend_score if trend_anomaly else 0)
        
        if SKLEARN_AVAILABLE:
            ml_anomaly, ml_score = self.ml_detection(value)
            results.append(("isolation_forest", ml_anomaly, ml_score))
            scores.append(ml_score if ml_anomaly else 0)
        
        # Voting: if 2 or more methods detect anomaly
        anomaly_votes = sum(1 for _, is_anomaly, _ in results if is_anomaly)
        is_anomaly = anomaly_votes >= 2
        
        # Calculate severity based on number of methods and scores
        avg_score = np.mean(scores) if scores else 0
        
        if avg_score > 5:
            severity = "high"
        elif avg_score > 2:
            severity = "medium"
        else:
            severity = "low"
        
        # Calculate expected value (moving average)
        expected = np.mean(list(self.value_history)[-5:]) if len(self.value_history) >= 5 else value
        
        # Build detailed message
        detecting_methods = [name for name, is_anom, _ in results if is_anom]
        message = f"Anomaly detected by {', '.join(detecting_methods)}. "
        message += f"Value: {value:.2f} vs expected: {expected:.2f}"
        
        return AnomalyResult(
            is_anomaly=is_anomaly,
            score=avg_score,
            method="ensemble",
            severity=severity,
            expected_value=expected,
            actual_value=value,
            message=message
        )
    
    def get_statistics(self) -> Dict:
        """Get current statistical summary"""
        if len(self.value_history) < 2:
            return {}
        
        return {
            "mean": float(np.mean(self.value_history)),
            "std": float(np.std(self.value_history)),
            "min": float(np.min(self.value_history)),
            "max": float(np.max(self.value_history)),
            "q1": float(np.percentile(self.value_history, 25)),
            "q3": float(np.percentile(self.value_history, 75)),
            "trend": float(self.value_history[-1] - self.value_history[0]),
            "volatility": float(np.std(np.diff(self.value_history))) if len(self.value_history) > 1 else 0
        }

# Forecasting module
class TrafficForecaster:
    """Predict future traffic using time series analysis"""
    
    def __init__(self, history_size: int = 60):
        self.history_size = history_size
        self.history = deque(maxlen=history_size)
    
    def add_value(self, value: float):
        self.history.append(value)
    
    def predict_next(self, method: str = "auto") -> Tuple[float, float]:
        """
        Predict next value with confidence interval
        Methods: simple_moving_average, weighted_ma, exponential_smoothing, holt_winters
        """
        if len(self.history) < 5:
            return self.history[-1] if self.history else 0, 0.5
        
        predictions = []
        
        # Simple Moving Average (last 5)
        sma = np.mean(list(self.history)[-5:])
        predictions.append(sma)
        
        # Weighted Moving Average (more weight to recent)
        weights = [0.4, 0.3, 0.2, 0.1]
        recent_4 = list(self.history)[-4:]
        wma = sum(w * v for w, v in zip(weights, recent_4)) / sum(weights)
        predictions.append(wma)
        
        # Exponential Smoothing
        alpha = 0.3
        exp_smooth = self.history[-1]
        for val in list(self.history)[-10:]:
            exp_smooth = alpha * val + (1 - alpha) * exp_smooth
        predictions.append(exp_smooth)
        
        # Linear Regression on last 10 points
        if len(self.history) >= 10:
            recent = list(self.history)[-10:]
            x = np.arange(len(recent))
            z = np.polyfit(x, recent, 1)
            p = np.poly1d(z)
            linear_pred = p(len(recent))
            predictions.append(linear_pred)
        
        # Final prediction (median of all methods)
        final_pred = np.median(predictions)
        
        # Confidence (based on variance of predictions)
        confidence = 1.0 - min(1.0, np.std(predictions) / max(final_pred, 0.1))
        confidence = max(0.3, min(0.95, confidence))
        
        return round(final_pred, 2), round(confidence, 2)
    
    def predict_future(self, steps: int = 5) -> List[Dict]:
        """Predict multiple future steps"""
        predictions = []
        temp_history = list(self.history)
        
        for i in range(steps):
            # Use current history to predict next
            pred, conf = self.predict_next()
            predictions.append({
                "step": i + 1,
                "value": pred,
                "confidence": conf
            })
            # Add prediction to temp history for next iteration
            temp_history.append(pred)
        
        return predictions