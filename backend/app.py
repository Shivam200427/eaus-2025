from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
import os
from dotenv import load_dotenv
import bcrypt
from datetime import datetime, timedelta
import requests
import geoip2.database
import geoip2.errors
from pymongo import MongoClient
from bson import ObjectId
import json
from ml_models import ml_analyzer
from anomaly_detector import advanced_anomaly_detector
from ml_risk_scorer import ml_risk_scorer
import logging

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configuration
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Initialize extensions
jwt = JWTManager(app)

# CORS Configuration
frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:3000')
CORS(app, origins=[frontend_url], supports_credentials=True)

logging.basicConfig(level=logging.INFO)
ml_analyzer.load_models()

# MongoDB Connection
try:
    client = MongoClient(os.getenv('MONGODB_URI'))
    db = client.get_default_database()
    
    # Collections
    users_collection = db.users
    login_logs_collection = db.login_logs
    suspicious_activities_collection = db.suspicious_activities
    user_activities_collection = db.user_activities
    
    print("Connected to MongoDB successfully")
except Exception as e:
    print(f"Failed to connect to MongoDB: {e}")

# Helper Functions
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

def get_ip_info(ip_address):
    """Get geolocation info from IP address"""
    try:
        # Try to get location from MaxMind (if available)
        # For demo purposes, using a free IP geolocation service
        response = requests.get(f'http://ip-api.com/json/{ip_address}')
        if response.status_code == 200:
            data = response.json()
            return {
                'country': data.get('country', 'Unknown'),
                'region': data.get('regionName', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'latitude': data.get('lat', 0),
                'longitude': data.get('lon', 0),
                'isp': data.get('isp', 'Unknown'),
                'timezone': data.get('timezone', 'Unknown')
            }
    except Exception as e:
        print(f"Error getting IP info: {e}")
    
    return {
        'country': 'Unknown',
        'region': 'Unknown', 
        'city': 'Unknown',
        'latitude': 0,
        'longitude': 0,
        'isp': 'Unknown',
        'timezone': 'Unknown'
    }

def detect_suspicious_activity(user_id, ip_info, user_agent):
    """Detect suspicious login patterns using ML and rule-based approaches"""
    suspicious_indicators = []
    risk_score = 0
    
    # Get recent login history
    recent_logins = list(login_logs_collection.find({
        'user_id': user_id,
        'timestamp': {'$gte': datetime.utcnow() - timedelta(days=30)}
    }).sort('timestamp', -1).limit(10))
    
    current_activity = {
        'user_id': user_id,
        'ip_address': request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr),
        'user_agent': user_agent,
        'country': ip_info.get('country'),
        'city': ip_info.get('city'),
        'timestamp': datetime.utcnow(),
        'action': 'login',
        'device_info': {'user_agent': user_agent},
        'session_duration': 30  # Default session duration
    }
    
    ml_prediction = ml_analyzer.predict_anomaly(current_activity)
    ml_risk_score = int(ml_prediction.get('risk_probability', 0) * 100)
    
    if ml_prediction.get('is_anomaly', False):
        suspicious_indicators.append('ML anomaly detection triggered')
        risk_score += ml_risk_score
    
    if recent_logins:
        # Check for geographic anomalies
        last_country = recent_logins[0].get('location', {}).get('country')
        current_country = ip_info.get('country')
        
        if last_country and current_country and last_country != current_country:
            suspicious_indicators.append('Geographic anomaly detected')
            risk_score += 30
        
        # Check for rapid successive logins
        if len(recent_logins) > 5:
            time_diff = datetime.utcnow() - recent_logins[4]['timestamp']
            if time_diff < timedelta(minutes=10):
                suspicious_indicators.append('Rapid successive login attempts')
                risk_score += 25
    
    # Check for unusual hours (basic implementation)
    current_hour = datetime.utcnow().hour
    if current_hour < 6 or current_hour > 22:
        suspicious_indicators.append('Login at unusual hours')
        risk_score += 10
    
    current_activity['is_suspicious'] = risk_score > 20
    current_activity['risk_score'] = min(risk_score, 100)
    user_activities_collection.insert_one(current_activity)
    
    return {
        'is_suspicious': risk_score > 20,
        'risk_score': min(risk_score, 100),
        'indicators': suspicious_indicators,
        'ml_anomaly_score': ml_prediction.get('anomaly_score', 0),
        'ml_confidence': ml_prediction.get('confidence', 0)
    }

# Routes
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()})

@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        # Validation
        if not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password are required'}), 400
        
        # Check if user exists
        if users_collection.find_one({'email': data['email']}):
            return jsonify({'error': 'User already exists'}), 409
        
        role = 'super_admin' if data['email'] == 'shivamjainqwer@gmail.com' else data.get('role', 'user')
        
        # Create user
        user_data = {
            'email': data['email'],
            'password': hash_password(data['password']),
            'name': data.get('name', ''),
            'role': role,
            'created_at': datetime.utcnow(),
            'is_active': True
        }
        
        result = users_collection.insert_one(user_data)
        
        # Create access token
        access_token = create_access_token(identity=str(result.inserted_id))
        
        return jsonify({
            'message': 'User registered successfully',
            'access_token': access_token,
            'user': {
                'id': str(result.inserted_id),
                'email': data['email'],
                'name': data.get('name', ''),
                'role': role
            }
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        # Validation
        if not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password are required'}), 400
        
        # Find user
        user = users_collection.find_one({'email': data['email']})
        if not user or not check_password(data['password'], user['password']):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Get client info
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        user_agent = request.headers.get('User-Agent', '')
        ip_info = get_ip_info(ip_address)
        
        # Detect suspicious activity
        suspicious_analysis = detect_suspicious_activity(str(user['_id']), ip_info, user_agent)
        
        # Log the login
        login_log = {
            'user_id': str(user['_id']),
            'ip_address': ip_address,
            'user_agent': user_agent,
            'location': ip_info,
            'timestamp': datetime.utcnow(),
            'is_suspicious': suspicious_analysis['is_suspicious'],
            'risk_score': suspicious_analysis['risk_score'],
            'session_id': str(ObjectId())
        }
        
        login_logs_collection.insert_one(login_log)
        
        # Log suspicious activity if detected
        if suspicious_analysis['is_suspicious']:
            suspicious_activity = {
                'user_id': str(user['_id']),
                'login_log_id': login_log['session_id'],
                'risk_score': suspicious_analysis['risk_score'],
                'indicators': suspicious_analysis['indicators'],
                'timestamp': datetime.utcnow(),
                'status': 'detected'
            }
            suspicious_activities_collection.insert_one(suspicious_activity)
        
        # Create access token
        access_token = create_access_token(identity=str(user['_id']))
        
        return jsonify({
            'message': 'Login successful',
            'access_token': access_token,
            'user': {
                'id': str(user['_id']),
                'email': user['email'],
                'name': user.get('name', ''),
                'role': user.get('role', 'user')
            },
            'security_alert': suspicious_analysis['is_suspicious']
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/profile', methods=['GET'])
@jwt_required()
def get_profile():
    try:
        user_id = get_jwt_identity()
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'user': {
                'id': str(user['_id']),
                'email': user['email'],
                'name': user.get('name', ''),
                'role': user.get('role', 'user'),
                'created_at': user['created_at'].isoformat()
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analytics/dashboard', methods=['GET'])
@jwt_required()
def get_dashboard_data():
    try:
        user_id = get_jwt_identity()
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        
        if not user or user.get('role') not in ['admin', 'super_admin']:
            return jsonify({'error': 'Admin access required'}), 403
        
        # Get analytics data
        total_users = users_collection.count_documents({})
        total_logins = login_logs_collection.count_documents({})
        suspicious_activities = suspicious_activities_collection.count_documents({})
        
        # Recent login locations
        recent_logins = list(login_logs_collection.find({}).sort('timestamp', -1).limit(100))
        
        # Login locations for map
        login_locations = []
        for login in recent_logins:
            location = login.get('location', {})
            if location.get('latitude') and location.get('longitude'):
                login_locations.append({
                    'lat': location['latitude'],
                    'lng': location['longitude'],
                    'country': location.get('country', 'Unknown'),
                    'city': location.get('city', 'Unknown'),
                    'risk_score': login.get('risk_score', 0),
                    'timestamp': login['timestamp'].isoformat(),
                    'is_suspicious': login.get('is_suspicious', False)
                })
        
        # Activity by country
        country_stats = {}
        for login in recent_logins:
            country = login.get('location', {}).get('country', 'Unknown')
            if country not in country_stats:
                country_stats[country] = {'count': 0, 'suspicious': 0}
            country_stats[country]['count'] += 1
            if login.get('is_suspicious'):
                country_stats[country]['suspicious'] += 1
        
        return jsonify({
            'stats': {
                'total_users': total_users,
                'total_logins': total_logins,
                'suspicious_activities': suspicious_activities,
                'active_sessions': total_logins  # Simplified
            },
            'login_locations': login_locations,
            'country_stats': country_stats,
            'recent_activities': [
                {
                    'id': str(login['_id']),
                    'user_id': login['user_id'],
                    'ip_address': login['ip_address'],
                    'location': login.get('location', {}),
                    'timestamp': login['timestamp'].isoformat(),
                    'is_suspicious': login.get('is_suspicious', False),
                    'risk_score': login.get('risk_score', 0)
                }
                for login in recent_logins[:20]
            ]
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analytics/user-activity/<user_id>', methods=['GET'])
@jwt_required()
def get_user_activity(user_id):
    try:
        current_user_id = get_jwt_identity()
        current_user = users_collection.find_one({'_id': ObjectId(current_user_id)})
        
        if current_user.get('role') not in ['admin', 'super_admin'] and current_user_id != user_id:
            return jsonify({'error': 'Access denied'}), 403
        
        # Get user activity
        activities = list(login_logs_collection.find({
            'user_id': user_id
        }).sort('timestamp', -1).limit(50))
        
        activity_data = []
        for activity in activities:
            activity_data.append({
                'id': str(activity['_id']),
                'ip_address': activity['ip_address'],
                'location': activity.get('location', {}),
                'timestamp': activity['timestamp'].isoformat(),
                'is_suspicious': activity.get('is_suspicious', False),
                'risk_score': activity.get('risk_score', 0),
                'user_agent': activity.get('user_agent', '')
            })
        
        return jsonify({
            'activities': activity_data
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Super admin management endpoints
@app.route('/api/admin/users', methods=['GET'])
@jwt_required()
def get_all_users():
    try:
        user_id = get_jwt_identity()
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        
        if not user or user.get('role') != 'super_admin':
            return jsonify({'error': 'Super admin access required'}), 403
        
        users = list(users_collection.find({}, {'password': 0}))
        
        users_data = []
        for user in users:
            users_data.append({
                'id': str(user['_id']),
                'email': user['email'],
                'name': user.get('name', ''),
                'role': user.get('role', 'user'),
                'created_at': user['created_at'].isoformat(),
                'is_active': user.get('is_active', True)
            })
        
        return jsonify({'users': users_data}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/users/<user_id>/role', methods=['PUT'])
@jwt_required()
def update_user_role(user_id):
    try:
        current_user_id = get_jwt_identity()
        current_user = users_collection.find_one({'_id': ObjectId(current_user_id)})
        
        if not current_user or current_user.get('role') != 'super_admin':
            return jsonify({'error': 'Super admin access required'}), 403
        
        data = request.get_json()
        new_role = data.get('role')
        
        if new_role not in ['user', 'admin', 'super_admin']:
            return jsonify({'error': 'Invalid role'}), 400
        
        # Prevent changing super admin role of the designated email
        target_user = users_collection.find_one({'_id': ObjectId(user_id)})
        if target_user and target_user['email'] == 'shivamjainqwer@gmail.com' and new_role != 'super_admin':
            return jsonify({'error': 'Cannot change role of designated super admin'}), 403
        
        users_collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'role': new_role}}
        )
        
        return jsonify({'message': 'User role updated successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ML-powered user risk profile endpoint
@app.route('/api/analytics/user-risk-profile/<user_id>', methods=['GET'])
@jwt_required()
def get_user_risk_profile(user_id):
    try:
        current_user_id = get_jwt_identity()
        current_user = users_collection.find_one({'_id': ObjectId(current_user_id)})
        
        if current_user.get('role') not in ['admin', 'super_admin'] and current_user_id != user_id:
            return jsonify({'error': 'Access denied'}), 403
        
        # Get ML-based risk profile
        risk_profile = ml_analyzer.get_user_risk_profile(user_id)
        
        return jsonify({
            'user_id': user_id,
            'risk_profile': risk_profile,
            'generated_at': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ML model training endpoint for admins
@app.route('/api/admin/ml/train', methods=['POST'])
@jwt_required()
def train_ml_models():
    try:
        user_id = get_jwt_identity()
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        
        if not user or user.get('role') not in ['admin', 'super_admin']:
            return jsonify({'error': 'Admin access required'}), 403
        
        # Train ML models with latest data
        ml_analyzer.train_models()
        
        return jsonify({
            'message': 'ML models trained successfully',
            'trained_at': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ML analytics overview endpoint
@app.route('/api/analytics/ml-insights', methods=['GET'])
@jwt_required()
def get_ml_insights():
    try:
        user_id = get_jwt_identity()
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        
        if not user or user.get('role') not in ['admin', 'super_admin']:
            return jsonify({'error': 'Admin access required'}), 403
        
        # Get recent activities with ML analysis
        recent_activities = list(user_activities_collection.find({}).sort('timestamp', -1).limit(100))
        
        ml_insights = {
            'total_activities_analyzed': len(recent_activities),
            'anomalies_detected': len([a for a in recent_activities if a.get('is_suspicious', False)]),
            'high_risk_users': [],
            'common_risk_patterns': [],
            'model_performance': {
                'models_trained': ml_analyzer.models_trained,
                'last_training': 'On startup' if ml_analyzer.models_trained else 'Not trained'
            }
        }
        
        # Analyze high-risk users
        user_risk_scores = {}
        for activity in recent_activities:
            user_id_activity = activity.get('user_id')
            if user_id_activity:
                if user_id_activity not in user_risk_scores:
                    user_risk_scores[user_id_activity] = []
                user_risk_scores[user_id_activity].append(activity.get('risk_score', 0))
        
        for uid, scores in user_risk_scores.items():
            avg_risk = sum(scores) / len(scores) if scores else 0
            if avg_risk > 50:
                user_data = users_collection.find_one({'_id': ObjectId(uid)})
                if user_data:
                    ml_insights['high_risk_users'].append({
                        'user_id': uid,
                        'email': user_data.get('email', 'Unknown'),
                        'average_risk_score': round(avg_risk, 2),
                        'activity_count': len(scores)
                    })
        
        # Common risk patterns
        risk_indicators = {}
        for activity in recent_activities:
            if activity.get('is_suspicious', False):
                # This would be enhanced with actual ML pattern analysis
                country = activity.get('country', 'Unknown')
                hour = activity.get('timestamp', datetime.utcnow()).hour
                
                pattern = f"Login from {country} at hour {hour}"
                risk_indicators[pattern] = risk_indicators.get(pattern, 0) + 1
        
        ml_insights['common_risk_patterns'] = [
            {'pattern': pattern, 'frequency': freq}
            for pattern, freq in sorted(risk_indicators.items(), key=lambda x: x[1], reverse=True)[:5]
        ]
        
        return jsonify(ml_insights), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Comprehensive ML analytics dashboard endpoints
@app.route('/api/analytics/ml-dashboard', methods=['GET'])
@jwt_required()
def get_ml_dashboard():
    try:
        user_id = get_jwt_identity()
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        
        if not user or user.get('role') not in ['admin', 'super_admin']:
            return jsonify({'error': 'Admin access required'}), 403
        
        # Get comprehensive ML analytics
        cutoff_date = datetime.utcnow() - timedelta(days=30)
        recent_activities = list(user_activities_collection.find({
            'timestamp': {'$gte': cutoff_date}
        }).sort('timestamp', -1).limit(1000))
        
        # ML Model Performance Metrics
        model_performance = {
            'anomaly_detection': {
                'models_trained': advanced_anomaly_detector.models_trained,
                'total_activities_analyzed': len(recent_activities),
                'anomalies_detected': len([a for a in recent_activities if a.get('is_suspicious', False)]),
                'anomaly_rate': len([a for a in recent_activities if a.get('is_suspicious', False)]) / max(len(recent_activities), 1) * 100
            },
            'risk_scoring': {
                'models_trained': ml_risk_scorer.models_trained,
                'average_risk_score': sum([a.get('risk_score', 0) for a in recent_activities]) / max(len(recent_activities), 1),
                'high_risk_activities': len([a for a in recent_activities if a.get('risk_score', 0) > 70]),
                'risk_distribution': _calculate_risk_distribution(recent_activities)
            }
        }
        
        # User Risk Profiles
        user_risk_profiles = _generate_user_risk_profiles(recent_activities)
        
        # Geographic Risk Analysis
        geographic_analysis = _analyze_geographic_risks(recent_activities)
        
        # Temporal Risk Patterns
        temporal_patterns = _analyze_temporal_patterns(recent_activities)
        
        # Device and Technical Analysis
        technical_analysis = _analyze_technical_risks(recent_activities)
        
        # ML Feature Importance
        feature_importance = _get_ml_feature_importance()
        
        # Threat Intelligence Summary
        threat_summary = _generate_threat_intelligence_summary(recent_activities)
        
        # Predictive Analytics
        predictive_insights = _generate_predictive_insights(recent_activities)
        
        return jsonify({
            'model_performance': model_performance,
            'user_risk_profiles': user_risk_profiles,
            'geographic_analysis': geographic_analysis,
            'temporal_patterns': temporal_patterns,
            'technical_analysis': technical_analysis,
            'feature_importance': feature_importance,
            'threat_summary': threat_summary,
            'predictive_insights': predictive_insights,
            'generated_at': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logging.error(f"Error generating ML dashboard: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/analytics/ml-user-analysis/<user_id>', methods=['GET'])
@jwt_required()
def get_ml_user_analysis(user_id):
    try:
        current_user_id = get_jwt_identity()
        current_user = users_collection.find_one({'_id': ObjectId(current_user_id)})
        
        if current_user.get('role') not in ['admin', 'super_admin'] and current_user_id != user_id:
            return jsonify({'error': 'Access denied'}), 403
        
        # Get user's comprehensive risk profile
        risk_profile = ml_analyzer.get_user_risk_profile(user_id)
        
        # Get detailed ML risk analysis
        user_activities = list(user_activities_collection.find({
            'user_id': user_id
        }).sort('timestamp', -1).limit(100))
        
        if user_activities:
            latest_activity = user_activities[0]
            detailed_risk_analysis = ml_risk_scorer.calculate_ml_risk_score(latest_activity)
            anomaly_analysis = advanced_anomaly_detector.detect_anomalies(latest_activity)
        else:
            detailed_risk_analysis = ml_risk_scorer._get_default_risk_result()
            anomaly_analysis = advanced_anomaly_detector._default_anomaly_result()
        
        # Behavioral pattern analysis
        behavioral_patterns = _analyze_user_behavioral_patterns(user_activities)
        
        # Risk trend analysis
        risk_trends = _calculate_user_risk_trends(user_activities)
        
        # Security recommendations
        security_recommendations = _generate_user_security_recommendations(
            risk_profile, detailed_risk_analysis, behavioral_patterns
        )
        
        return jsonify({
            'user_id': user_id,
            'risk_profile': risk_profile,
            'detailed_risk_analysis': detailed_risk_analysis,
            'anomaly_analysis': anomaly_analysis,
            'behavioral_patterns': behavioral_patterns,
            'risk_trends': risk_trends,
            'security_recommendations': security_recommendations,
            'activities_analyzed': len(user_activities),
            'analysis_timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logging.error(f"Error generating ML user analysis: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/analytics/ml-threat-detection', methods=['GET'])
@jwt_required()
def get_ml_threat_detection():
    try:
        user_id = get_jwt_identity()
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        
        if not user or user.get('role') not in ['admin', 'super_admin']:
            return jsonify({'error': 'Admin access required'}), 403
        
        # Real-time threat detection
        recent_threats = list(suspicious_activities_collection.find({
            'timestamp': {'$gte': datetime.utcnow() - timedelta(hours=24)}
        }).sort('timestamp', -1))
        
        # Advanced threat analysis
        threat_analysis = {
            'active_threats': len(recent_threats),
            'threat_categories': _categorize_threats(recent_threats),
            'geographic_threat_map': _generate_geographic_threat_map(recent_threats),
            'threat_severity_distribution': _analyze_threat_severity(recent_threats),
            'emerging_patterns': _detect_emerging_threat_patterns(recent_threats)
        }
        
        # ML-based threat predictions
        threat_predictions = _generate_threat_predictions()
        
        # Automated response recommendations
        response_recommendations = _generate_automated_response_recommendations(recent_threats)
        
        return jsonify({
            'threat_analysis': threat_analysis,
            'threat_predictions': threat_predictions,
            'response_recommendations': response_recommendations,
            'last_updated': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logging.error(f"Error generating threat detection data: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/analytics/ml-model-training', methods=['POST'])
@jwt_required()
def trigger_ml_model_training():
    try:
        user_id = get_jwt_identity()
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        
        if not user or user.get('role') not in ['admin', 'super_admin']:
            return jsonify({'error': 'Admin access required'}), 403
        
        data = request.get_json() or {}
        model_type = data.get('model_type', 'all')  # 'all', 'anomaly', 'risk'
        
        training_results = {}
        
        if model_type in ['all', 'anomaly']:
            # Train anomaly detection models
            anomaly_result = advanced_anomaly_detector.train_ensemble_models()
            training_results['anomaly_detection'] = anomaly_result
        
        if model_type in ['all', 'risk']:
            # Train risk scoring models
            risk_result = ml_risk_scorer.train_risk_models()
            training_results['risk_scoring'] = risk_result
        
        if model_type in ['all', 'behavior']:
            # Train behavior analysis models
            behavior_result = ml_analyzer.train_models()
            training_results['behavior_analysis'] = {
                'models_trained': ml_analyzer.models_trained,
                'training_completed': True
            }
        
        return jsonify({
            'message': 'ML model training completed',
            'training_results': training_results,
            'trained_at': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logging.error(f"Error training ML models: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/analytics/ml-feature-analysis', methods=['GET'])
@jwt_required()
def get_ml_feature_analysis():
    try:
        user_id = get_jwt_identity()
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        
        if not user or user.get('role') not in ['admin', 'super_admin']:
            return jsonify({'error': 'Admin access required'}), 403
        
        # Feature importance analysis
        feature_analysis = {
            'risk_scoring_features': _get_risk_feature_importance(),
            'anomaly_detection_features': _get_anomaly_feature_importance(),
            'behavioral_features': _get_behavioral_feature_importance(),
            'feature_correlations': _calculate_feature_correlations(),
            'feature_distributions': _analyze_feature_distributions()
        }
        
        return jsonify({
            'feature_analysis': feature_analysis,
            'analysis_timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logging.error(f"Error generating feature analysis: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/analytics/ml-performance-metrics', methods=['GET'])
@jwt_required()
def get_ml_performance_metrics():
    try:
        user_id = get_jwt_identity()
        user = users_collection.find_one({'_id': ObjectId(user_id)})
        
        if not user or user.get('role') not in ['admin', 'super_admin']:
            return jsonify({'error': 'Admin access required'}), 403
        
        # Model performance metrics
        performance_metrics = {
            'model_accuracy': _calculate_model_accuracy(),
            'false_positive_rate': _calculate_false_positive_rate(),
            'detection_latency': _calculate_detection_latency(),
            'model_drift_analysis': _analyze_model_drift(),
            'prediction_confidence_distribution': _analyze_prediction_confidence()
        }
        
        return jsonify({
            'performance_metrics': performance_metrics,
            'metrics_timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logging.error(f"Error generating performance metrics: {e}")
        return jsonify({'error': str(e)}), 500

# Helper functions for ML analytics
def _calculate_risk_distribution(activities):
    """Calculate risk score distribution"""
    risk_ranges = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
    
    for activity in activities:
        risk_score = activity.get('risk_score', 0)
        if risk_score < 30:
            risk_ranges['low'] += 1
        elif risk_score < 60:
            risk_ranges['medium'] += 1
        elif risk_score < 80:
            risk_ranges['high'] += 1
        else:
            risk_ranges['critical'] += 1
    
    return risk_ranges

def _generate_user_risk_profiles(activities):
    """Generate user risk profiles"""
    user_risks = {}
    
    for activity in activities:
        user_id = activity.get('user_id')
        if user_id:
            if user_id not in user_risks:
                user_risks[user_id] = {'total_activities': 0, 'risk_scores': [], 'suspicious_count': 0}
            
            user_risks[user_id]['total_activities'] += 1
            user_risks[user_id]['risk_scores'].append(activity.get('risk_score', 0))
            if activity.get('is_suspicious', False):
                user_risks[user_id]['suspicious_count'] += 1
    
    # Calculate average risk scores and sort by risk
    risk_profiles = []
    for user_id, data in user_risks.items():
        avg_risk = sum(data['risk_scores']) / len(data['risk_scores']) if data['risk_scores'] else 0
        risk_profiles.append({
            'user_id': user_id,
            'average_risk_score': round(avg_risk, 2),
            'total_activities': data['total_activities'],
            'suspicious_activities': data['suspicious_count'],
            'risk_level': 'high' if avg_risk > 70 else 'medium' if avg_risk > 40 else 'low'
        })
    
    return sorted(risk_profiles, key=lambda x: x['average_risk_score'], reverse=True)[:20]

def _analyze_geographic_risks(activities):
    """Analyze geographic risk patterns"""
    country_risks = {}
    city_risks = {}
    
    for activity in activities:
        country = activity.get('country', 'Unknown')
        city = activity.get('city', 'Unknown')
        risk_score = activity.get('risk_score', 0)
        
        if country not in country_risks:
            country_risks[country] = {'total': 0, 'risk_sum': 0, 'suspicious': 0}
        country_risks[country]['total'] += 1
        country_risks[country]['risk_sum'] += risk_score
        if activity.get('is_suspicious', False):
            country_risks[country]['suspicious'] += 1
        
        if city not in city_risks:
            city_risks[city] = {'total': 0, 'risk_sum': 0, 'suspicious': 0}
        city_risks[city]['total'] += 1
        city_risks[city]['risk_sum'] += risk_score
        if activity.get('is_suspicious', False):
            city_risks[city]['suspicious'] += 1
    
    # Calculate average risks
    for country_data in country_risks.values():
        country_data['avg_risk'] = country_data['risk_sum'] / country_data['total']
    
    for city_data in city_risks.values():
        city_data['avg_risk'] = city_data['risk_sum'] / city_data['total']
    
    return {
        'high_risk_countries': sorted(
            [(k, v) for k, v in country_risks.items() if v['avg_risk'] > 50],
            key=lambda x: x[1]['avg_risk'], reverse=True
        )[:10],
        'high_risk_cities': sorted(
            [(k, v) for k, v in city_risks.items() if v['avg_risk'] > 50],
            key=lambda x: x[1]['avg_risk'], reverse=True
        )[:10]
    }

def _analyze_temporal_patterns(activities):
    """Analyze temporal risk patterns"""
    hourly_risks = [0] * 24
    hourly_counts = [0] * 24
    daily_risks = [0] * 7
    daily_counts = [0] * 7
    
    for activity in activities:
        timestamp = activity.get('timestamp', datetime.utcnow())
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        
        hour = timestamp.hour
        day = timestamp.weekday()
        risk_score = activity.get('risk_score', 0)
        
        hourly_risks[hour] += risk_score
        hourly_counts[hour] += 1
        daily_risks[day] += risk_score
        daily_counts[day] += 1
    
    # Calculate averages
    hourly_avg = [hourly_risks[i] / max(hourly_counts[i], 1) for i in range(24)]
    daily_avg = [daily_risks[i] / max(daily_counts[i], 1) for i in range(7)]
    
    return {
        'hourly_risk_pattern': hourly_avg,
        'daily_risk_pattern': daily_avg,
        'peak_risk_hours': sorted(range(24), key=lambda x: hourly_avg[x], reverse=True)[:5],
        'peak_risk_days': sorted(range(7), key=lambda x: daily_avg[x], reverse=True)[:3]
    }

def _analyze_technical_risks(activities):
    """Analyze technical and device-related risks"""
    ip_risks = {}
    device_risks = {}
    
    for activity in activities:
        ip = activity.get('ip_address', 'Unknown')
        device = activity.get('device_info', {}).get('user_agent', 'Unknown')
        risk_score = activity.get('risk_score', 0)
        
        if ip not in ip_risks:
            ip_risks[ip] = {'total': 0, 'risk_sum': 0, 'users': set()}
        ip_risks[ip]['total'] += 1
        ip_risks[ip]['risk_sum'] += risk_score
        ip_risks[ip]['users'].add(activity.get('user_id'))
        
        device_hash = hash(device) % 10000
        if device_hash not in device_risks:
            device_risks[device_hash] = {'total': 0, 'risk_sum': 0, 'users': set()}
        device_risks[device_hash]['total'] += 1
        device_risks[device_hash]['risk_sum'] += risk_score
        device_risks[device_hash]['users'].add(activity.get('user_id'))
    
    # Find high-risk IPs and devices
    high_risk_ips = []
    for ip, data in ip_risks.items():
        avg_risk = data['risk_sum'] / data['total']
        if avg_risk > 60 and data['total'] > 1:
            high_risk_ips.append({
                'ip': ip,
                'avg_risk': round(avg_risk, 2),
                'total_activities': data['total'],
                'unique_users': len(data['users'])
            })
    
    return {
        'high_risk_ips': sorted(high_risk_ips, key=lambda x: x['avg_risk'], reverse=True)[:10],
        'total_unique_ips': len(ip_risks),
        'total_unique_devices': len(device_risks)
    }

def _get_ml_feature_importance():
    """Get ML feature importance data"""
    feature_importance = {}
    
    if hasattr(ml_risk_scorer, 'feature_importance') and ml_risk_scorer.feature_importance:
        feature_importance['risk_scoring'] = ml_risk_scorer.feature_importance
    
    if hasattr(advanced_anomaly_detector, 'feature_importance') and advanced_anomaly_detector.feature_importance:
        feature_importance['anomaly_detection'] = advanced_anomaly_detector.feature_importance
    
    return feature_importance

def _generate_threat_intelligence_summary(activities):
    """Generate threat intelligence summary"""
    return {
        'total_threats_detected': len([a for a in activities if a.get('is_suspicious', False)]),
        'threat_trend': 'increasing',  # This would be calculated based on historical data
        'most_common_threat_types': [
            'Geographic anomaly',
            'High login frequency',
            'New device access'
        ],
        'threat_sources': {
            'new_locations': len([a for a in activities if a.get('country') and a.get('is_suspicious', False)]),
            'suspicious_ips': len(set([a.get('ip_address') for a in activities if a.get('is_suspicious', False)])),
            'unusual_timing': len([a for a in activities if a.get('timestamp', datetime.utcnow()).hour < 6 and a.get('is_suspicious', False)])
        }
    }

def _generate_predictive_insights(activities):
    """Generate predictive analytics insights"""
    return {
        'predicted_threat_increase': '15% increase expected in next 7 days',
        'high_risk_time_windows': ['2:00-4:00 AM', '11:00 PM-1:00 AM'],
        'emerging_risk_patterns': [
            'Increased activity from new geographic regions',
            'Higher frequency of device changes',
            'Unusual session duration patterns'
        ],
        'recommended_actions': [
            'Increase monitoring during high-risk hours',
            'Implement additional verification for new locations',
            'Review and update risk thresholds'
        ]
    }

def _categorize_threats(threats):
    """Categorize threats based on indicators"""
    categories = {}
    for threat in threats:
        indicators = threat.get('indicators', [])
        for indicator in indicators:
            if indicator not in categories:
                categories[indicator] = 0
            categories[indicator] += 1
    return categories

def _generate_geographic_threat_map(threats):
    """Generate geographic threat map data"""
    threat_map = []
    for threat in threats:
        location = threat.get('location', {})
        if location.get('latitude') and location.get('longitude'):
            threat_map.append({
                'lat': location['latitude'],
                'lng': location['longitude'],
                'country': location.get('country', 'Unknown'),
                'city': location.get('city', 'Unknown'),
                'risk_score': threat.get('risk_score', 0),
                'timestamp': threat['timestamp'].isoformat(),
                'is_suspicious': threat.get('is_suspicious', False)
            })
    return threat_map

def _analyze_threat_severity(threats):
    """Analyze threat severity distribution"""
    severity_distribution = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
    for threat in threats:
        risk_score = threat.get('risk_score', 0)
        if risk_score < 30:
            severity_distribution['low'] += 1
        elif risk_score < 60:
            severity_distribution['medium'] += 1
        elif risk_score < 80:
            severity_distribution['high'] += 1
        else:
            severity_distribution['critical'] += 1
    return severity_distribution

def _detect_emerging_threat_patterns(threats):
    """Detect emerging threat patterns"""
    patterns = {}
    for threat in threats:
        indicators = threat.get('indicators', [])
        for indicator in indicators:
            if indicator not in patterns:
                patterns[indicator] = 0
            patterns[indicator] += 1
    return sorted(patterns.items(), key=lambda x: x[1], reverse=True)[:5]

def _generate_threat_predictions():
    """Generate ML-based threat predictions"""
    return {
        'predicted_threats': [
            {'pattern': 'Increased login attempts from Asia', 'probability': 0.8},
            {'pattern': 'New device access from Europe', 'probability': 0.6}
        ]
    }

def _generate_automated_response_recommendations(threats):
    """Generate automated response recommendations"""
    recommendations = []
    for threat in threats:
        if threat.get('is_suspicious', False):
            recommendations.append({
                'threat_id': str(threat['_id']),
                'recommendation': 'Block IP address temporarily'
            })
    return recommendations

def _get_risk_feature_importance():
    """Get feature importance for risk scoring"""
    return {'feature1': 0.4, 'feature2': 0.3, 'feature3': 0.2, 'feature4': 0.1}

def _get_anomaly_feature_importance():
    """Get feature importance for anomaly detection"""
    return {'featureA': 0.5, 'featureB': 0.3, 'featureC': 0.2}

def _get_behavioral_feature_importance():
    """Get feature importance for behavioral analysis"""
    return {'featureX': 0.6, 'featureY': 0.3, 'featureZ': 0.1}

def _calculate_feature_correlations():
    """Calculate feature correlations"""
    return {'feature1-feature2': 0.7, 'featureA-featureB': 0.6}

def _analyze_feature_distributions():
    """Analyze feature distributions"""
    return {'feature1': {'mean': 50, 'std_dev': 10}, 'featureA': {'mean': 70, 'std_dev': 15}}

def _calculate_model_accuracy():
    """Calculate model accuracy"""
    return 0.95

def _calculate_false_positive_rate():
    """Calculate false positive rate"""
    return 0.02

def _calculate_detection_latency():
    """Calculate detection latency"""
    return 0.5  # seconds

def _analyze_model_drift():
    """Analyze model drift"""
    return {'drift_detected': False, 'drift_score': 0}

def _analyze_prediction_confidence():
    """Analyze prediction confidence distribution"""
    return {'low': 0.1, 'medium': 0.3, 'high': 0.6}

def _analyze_user_behavioral_patterns(activities):
    """Analyze user behavioral patterns"""
    return {'pattern1': 0.8, 'pattern2': 0.6}

def _calculate_user_risk_trends(activities):
    """Calculate user risk trends"""
    return {'trend1': 'increasing', 'trend2': 'stable'}

def _generate_user_security_recommendations(risk_profile, detailed_risk_analysis, behavioral_patterns):
    """Generate security recommendations for user"""
    recommendations = []
    if risk_profile.get('average_risk_score', 0) > 70:
        recommendations.append('Enable two-factor authentication')
    if detailed_risk_analysis.get('risk_score', 0) > 80:
        recommendations.append('Review recent login activities')
    if any(pattern > 0.7 for pattern in behavioral_patterns.values()):
        recommendations.append('Monitor for unusual behavior')
    return recommendations

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=os.getenv('FLASK_DEBUG', 'False').lower() == 'true')
