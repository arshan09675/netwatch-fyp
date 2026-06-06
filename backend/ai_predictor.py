"""
AI TRAFFIC PREDICTOR - Neural network style traffic forecasting
"""

import numpy as np
from collections import deque
import time

class AIPredictor:
    """Advanced AI traffic prediction engine"""
    
    def __init__(self):
        self.history = deque(maxlen=2000)
        self.patterns = {}
        self.accuracy_history = deque(maxlen=100)
        self.weights = {
            'short': 0.35, 'medium': 0.25, 'long': 0.20,
            'hourly': 0.10, 'daily': 0.05, 'trend': 0.05
        }
    
    def add_data(self, value):
        """Add data point to history"""
        self.history.append({
            'timestamp': time.time(),
            'value': value
        })
        self._update_patterns(value)
    
    def _update_patterns(self, value):
        """Update pattern database"""
        now = time.localtime()
        hour = now.tm_hour
        day = now.tm_wday
        
        if hour not in self.patterns:
            self.patterns[hour] = deque(maxlen=100)
        self.patterns[hour].append(value)
        
        if day not in self.patterns:
            self.patterns[day] = deque(maxlen=500)
        self.patterns[day].append(value)
    
    def predict(self, minutes=10):
        """Predict traffic for next N minutes"""
        if len(self.history) < 30:
            return [{'minute': i, 'prediction': 0, 'confidence': 0.3} for i in range(1, minutes+1)]
        
        values = [d['value'] for d in list(self.history)]
        now = time.localtime()
        current_hour = now.tm_hour
        current_day = now.tm_wday
        
        # Get pattern averages
        hourly_avg = np.mean(list(self.patterns.get(current_hour, values[-60:]))) if self.patterns.get(current_hour) else np.mean(values[-60:])
        daily_avg = np.mean(list(self.patterns.get(current_day, values[-360:]))) if self.patterns.get(current_day) else np.mean(values[-360:])
        
        # Calculate trends
        short = np.mean(values[-5:]) if len(values) >= 5 else np.mean(values)
        medium = np.mean(values[-20:]) if len(values) >= 20 else np.mean(values)
        long = np.mean(values[-100:]) if len(values) >= 100 else np.mean(values)
        
        if len(values) >= 10:
            trend_slope = (values[-1] - values[-10]) / 10
        else:
            trend_slope = 0
        
        predictions = []
        
        for i in range(1, minutes+1):
            pred = (
                self.weights['short'] * short +
                self.weights['medium'] * medium +
                self.weights['long'] * long +
                self.weights['hourly'] * hourly_avg +
                self.weights['daily'] * daily_avg +
                self.weights['trend'] * (trend_slope * i * 0.3)
            )
            
            pred = max(0, round(pred, 2))
            confidence = max(0.3, min(0.95, 0.95 - (i / 60)))
            
            predictions.append({
                'minute': i,
                'prediction': pred,
                'confidence': round(confidence, 2)
            })
            
            short = short * 0.8 + pred * 0.2
        
        return predictions
    
    def get_insights(self):
        """Get AI insights"""
        if len(self.history) < 100:
            return {'status': 'learning', 'samples': len(self.history)}
        
        values = [d['value'] for d in list(self.history)]
        
        return {
            'status': 'trained',
            'avg': round(np.mean(values[-60:]), 2),
            'peak': round(max(values[-60:]), 2),
            'trend': 'increasing' if values[-1] > values[-10] else 'decreasing',
            'samples': len(self.history)
        }

ai_predictor = AIPredictor()