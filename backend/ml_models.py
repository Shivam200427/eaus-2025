import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from datetime import datetime, timedelta
import joblib
import os
from pymongo import MongoClient
from dotenv import load_dotenv
import logging

load_dotenv()

class UserBehaviorAnalyzer:
    def __init__(self):
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.risk_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.models_trained = False
        self.feature_columns = [
            'hour_of_day', 'day_of_week', 'login_frequency_24h', 
            'unique_locations_7d', 'avg_session_duration', 'failed_attempts_24h',
            'country_changes_7d', 'device_changes_7d', 'time_since_last_login'
        ]
        
    def extract_features(self, user_activities):
        """Extract ML features from user activity data"""
        features = []
        
        for activity in user_activities:
            try:
                login_time = activity.get('timestamp', datetime.now())
                if isinstance(login_time, str):
                    login_time = datetime.fromisoformat(login_time.replace('Z', '+00:00'))
                
                # Time-based features
                hour_of_day = login_time.hour
                day_of_week = login_time.weekday()
                
                # Calculate behavioral metrics
                user_id = activity.get('user_id')
                recent_activities = self._get_recent_activities(user_id, days=7)
                
                login_frequency_24h = len([a for a in recent_activities 
                                         if (datetime.now() - a.get('timestamp', datetime.now())).days < 1])
                
                unique_locations_7d = len(set([a.get('country', 'Unknown') for a in recent_activities]))
                
                avg_session_duration = np.mean([a.get('session_duration', 30) for a in recent_activities])
                
                failed_attempts_24h = len([a for a in recent_activities 
                                         if a.get('status') == 'failed' and 
                                         (datetime.now() - a.get('timestamp', datetime.now())).days < 1])
                
                country_changes_7d = self._count_country_changes(recent_activities)
                device_changes_7d = self._count_device_changes(recent_activities)
                
                # Time since last login (in hours)
                time_since_last = self._get_time_since_last_login(user_id)
                
                feature_vector = [
                    hour_of_day, day_of_week, login_frequency_24h,
                    unique_locations_7d, avg_session_duration, failed_attempts_24h,
                    country_changes_7d, device_changes_7d, time_since_last
                ]
                
                features.append({
                    'user_id': user_id,
                    'activity_id': activity.get('_id'),
                    'features': feature_vector,
                    'timestamp': login_time,
                    'is_suspicious': activity.get('is_suspicious', False)
                })
                
            except Exception as e:
                logging.error(f"Error extracting features: {e}")
                continue
                
        return features
    
    def _get_recent_activities(self, user_id, days=7):
        """Get recent activities for a user"""
        try:
            client = MongoClient(os.getenv('MONGODB_URI'))
            db = client[os.getenv('DATABASE_NAME', 'auth_system')]
            activities = db.user_activities
            
            cutoff_date = datetime.now() - timedelta(days=days)
            recent = list(activities.find({
                'user_id': user_id,
                'timestamp': {'$gte': cutoff_date}
            }).sort('timestamp', -1))
            
            return recent
        except Exception as e:
            logging.error(f"Error getting recent activities: {e}")
            return []
    
    def _count_country_changes(self, activities):
        """Count country changes in activities"""
        countries = [a.get('country') for a in activities if a.get('country')]
        changes = 0
        for i in range(1, len(countries)):
            if countries[i] != countries[i-1]:
                changes += 1
        return changes
    
    def _count_device_changes(self, activities):
        """Count device changes in activities"""
        devices = [a.get('device_info', {}).get('user_agent', '') for a in activities]
        unique_devices = len(set(devices))
        return unique_devices
    
    def _get_time_since_last_login(self, user_id):
        """Get hours since last login"""
        try:
            client = MongoClient(os.getenv('MONGODB_URI'))
            db = client[os.getenv('DATABASE_NAME', 'auth_system')]
            activities = db.user_activities
            
            last_activity = activities.find_one({
                'user_id': user_id,
                'action': 'login'
            }, sort=[('timestamp', -1)])
            
            if last_activity:
                last_time = last_activity.get('timestamp', datetime.now())
                if isinstance(last_time, str):
                    last_time = datetime.fromisoformat(last_time.replace('Z', '+00:00'))
                return (datetime.now() - last_time).total_seconds() / 3600
            return 0
        except Exception as e:
            logging.error(f"Error getting last login time: {e}")
            return 0
    
    def train_models(self, training_data=None):
        """Train ML models on user behavior data"""
        try:
            if training_data is None:
                training_data = self._collect_training_data()
            
            if len(training_data) < 10:
                logging.warning("Insufficient training data. Using synthetic data.")
                training_data = self._generate_synthetic_data()
            
            # Prepare features and labels
            X = np.array([item['features'] for item in training_data])
            y = np.array([1 if item['is_suspicious'] else 0 for item in training_data])
            
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            # Train anomaly detection model
            self.isolation_forest.fit(X_scaled)
            
            # Train risk classification model if we have labeled data
            if len(set(y)) > 1:
                X_train, X_test, y_train, y_test = train_test_split(
                    X_scaled, y, test_size=0.2, random_state=42
                )
                self.risk_classifier.fit(X_train, y_train)
                
                # Evaluate model
                y_pred = self.risk_classifier.predict(X_test)
                accuracy = accuracy_score(y_test, y_pred)
                logging.info(f"Risk classifier accuracy: {accuracy:.2f}")
            
            self.models_trained = True
            self._save_models()
            logging.info("ML models trained successfully")
            
        except Exception as e:
            logging.error(f"Error training models: {e}")
    
    def _collect_training_data(self):
        """Collect training data from database"""
        try:
            client = MongoClient(os.getenv('MONGODB_URI'))
            db = client[os.getenv('DATABASE_NAME', 'auth_system')]
            activities = db.user_activities
            
            # Get recent activities for training
            cutoff_date = datetime.now() - timedelta(days=30)
            recent_activities = list(activities.find({
                'timestamp': {'$gte': cutoff_date}
            }).limit(1000))
            
            return self.extract_features(recent_activities)
        except Exception as e:
            logging.error(f"Error collecting training data: {e}")
            return []
    
    def _generate_synthetic_data(self):
        """Generate synthetic training data for initial model training"""
        synthetic_data = []
        np.random.seed(42)
        
        for i in range(200):
            # Normal behavior patterns
            if i < 160:  # 80% normal
                features = [
                    np.random.randint(8, 18),  # Normal working hours
                    np.random.randint(0, 7),   # Any day of week
                    np.random.randint(1, 5),   # Normal login frequency
                    np.random.randint(1, 3),   # Few locations
                    np.random.normal(45, 15),  # Average session duration
                    np.random.randint(0, 2),   # Few failed attempts
                    np.random.randint(0, 2),   # Few country changes
                    np.random.randint(1, 3),   # Few device changes
                    np.random.exponential(12)  # Time since last login
                ]
                is_suspicious = False
            else:  # 20% suspicious
                features = [
                    np.random.choice([2, 3, 23, 24]),  # Unusual hours
                    np.random.randint(0, 7),
                    np.random.randint(10, 20),  # High login frequency
                    np.random.randint(5, 10),   # Many locations
                    np.random.normal(15, 5),    # Short sessions
                    np.random.randint(3, 10),   # Many failed attempts
                    np.random.randint(3, 8),    # Many country changes
                    np.random.randint(5, 10),   # Many device changes
                    np.random.exponential(2)    # Very recent login
                ]
                is_suspicious = True
            
            synthetic_data.append({
                'user_id': f'synthetic_user_{i}',
                'features': features,
                'is_suspicious': is_suspicious,
                'timestamp': datetime.now()
            })
        
        return synthetic_data
    
    def predict_anomaly(self, user_activity):
        """Predict if user activity is anomalous"""
        try:
            if not self.models_trained:
                self.train_models()
            
            features = self.extract_features([user_activity])
            if not features:
                return {'anomaly_score': 0, 'is_anomaly': False, 'confidence': 0}
            
            X = np.array([features[0]['features']])
            X_scaled = self.scaler.transform(X)
            
            # Get anomaly score from Isolation Forest
            anomaly_score = self.isolation_forest.decision_function(X_scaled)[0]
            is_anomaly = self.isolation_forest.predict(X_scaled)[0] == -1
            
            # Get risk probability from classifier
            risk_probability = 0
            if hasattr(self.risk_classifier, 'predict_proba'):
                risk_probability = self.risk_classifier.predict_proba(X_scaled)[0][1]
            
            return {
                'anomaly_score': float(anomaly_score),
                'is_anomaly': bool(is_anomaly),
                'risk_probability': float(risk_probability),
                'confidence': abs(float(anomaly_score))
            }
            
        except Exception as e:
            logging.error(f"Error predicting anomaly: {e}")
            return {'anomaly_score': 0, 'is_anomaly': False, 'confidence': 0}
    
    def get_user_risk_profile(self, user_id):
        """Generate comprehensive risk profile for a user"""
        try:
            recent_activities = self._get_recent_activities(user_id, days=30)
            if not recent_activities:
                return {'risk_level': 'low', 'risk_score': 0, 'insights': []}
            
            features_data = self.extract_features(recent_activities)
            if not features_data:
                return {'risk_level': 'low', 'risk_score': 0, 'insights': []}
            
            # Calculate aggregate risk metrics
            anomaly_scores = []
            risk_probabilities = []
            
            for activity in recent_activities[-10:]:  # Last 10 activities
                prediction = self.predict_anomaly(activity)
                anomaly_scores.append(prediction['anomaly_score'])
                risk_probabilities.append(prediction.get('risk_probability', 0))
            
            avg_anomaly_score = np.mean(anomaly_scores) if anomaly_scores else 0
            avg_risk_probability = np.mean(risk_probabilities) if risk_probabilities else 0
            
            # Determine risk level
            combined_score = (abs(avg_anomaly_score) * 50) + (avg_risk_probability * 50)
            
            if combined_score > 70:
                risk_level = 'high'
            elif combined_score > 40:
                risk_level = 'medium'
            else:
                risk_level = 'low'
            
            # Generate insights
            insights = self._generate_risk_insights(features_data[-1] if features_data else None)
            
            return {
                'risk_level': risk_level,
                'risk_score': min(100, max(0, combined_score)),
                'anomaly_score': avg_anomaly_score,
                'risk_probability': avg_risk_probability,
                'insights': insights,
                'activities_analyzed': len(recent_activities)
            }
            
        except Exception as e:
            logging.error(f"Error generating risk profile: {e}")
            return {'risk_level': 'low', 'risk_score': 0, 'insights': []}
    
    def _generate_risk_insights(self, feature_data):
        """Generate human-readable risk insights"""
        insights = []
        
        if not feature_data:
            return insights
        
        features = feature_data['features']
        
        # Analyze patterns
        if features[0] < 6 or features[0] > 22:  # Unusual hours
            insights.append("Login activity during unusual hours detected")
        
        if features[2] > 10:  # High login frequency
            insights.append("Unusually high login frequency in the last 24 hours")
        
        if features[3] > 5:  # Many locations
            insights.append("Access from multiple geographic locations")
        
        if features[5] > 3:  # Many failed attempts
            insights.append("Multiple failed login attempts detected")
        
        if features[6] > 2:  # Country changes
            insights.append("Frequent country changes in recent activity")
        
        if features[7] > 4:  # Device changes
            insights.append("Access from multiple devices detected")
        
        return insights
    
    def _save_models(self):
        """Save trained models to disk"""
        try:
            models_dir = 'models'
            os.makedirs(models_dir, exist_ok=True)
            
            joblib.dump(self.isolation_forest, f'{models_dir}/isolation_forest.pkl')
            joblib.dump(self.risk_classifier, f'{models_dir}/risk_classifier.pkl')
            joblib.dump(self.scaler, f'{models_dir}/scaler.pkl')
            
            logging.info("Models saved successfully")
        except Exception as e:
            logging.error(f"Error saving models: {e}")
    
    def load_models(self):
        """Load trained models from disk"""
        try:
            models_dir = 'models'
            
            if os.path.exists(f'{models_dir}/isolation_forest.pkl'):
                self.isolation_forest = joblib.load(f'{models_dir}/isolation_forest.pkl')
                self.risk_classifier = joblib.load(f'{models_dir}/risk_classifier.pkl')
                self.scaler = joblib.load(f'{models_dir}/scaler.pkl')
                self.models_trained = True
                logging.info("Models loaded successfully")
            else:
                logging.info("No saved models found, will train on first use")
        except Exception as e:
            logging.error(f"Error loading models: {e}")

# Initialize global ML analyzer
ml_analyzer = UserBehaviorAnalyzer()
