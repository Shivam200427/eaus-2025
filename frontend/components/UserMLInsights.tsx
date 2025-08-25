"use client"

import { useState, useEffect } from "react"
import axios from "axios"
import { Brain, Shield, TrendingUp, AlertTriangle, Activity } from "lucide-react"

interface UserMLInsightsProps {
  userId: string
  className?: string
}

interface MLUserAnalysis {
  user_id: string
  risk_profile: {
    risk_level: string
    risk_score: number
    insights: string[]
    activities_analyzed: number
  }
  detailed_risk_analysis: {
    risk_score: number
    risk_level: string
    confidence: number
    risk_factors: string[]
    protective_factors: string[]
    recommendations: string[]
  }
  behavioral_patterns: any
  risk_trends: any
  security_recommendations: string[]
}

export default function UserMLInsights({ userId, className = "" }: UserMLInsightsProps) {
  const [mlAnalysis, setMlAnalysis] = useState<MLUserAnalysis | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetchUserMLAnalysis()
  }, [userId])

  const fetchUserMLAnalysis = async () => {
    try {
      setLoading(true)
      const response = await axios.get(`/api/analytics/ml-user-analysis/${userId}`)
      setMlAnalysis(response.data)
      setError(null)
    } catch (err) {
      console.error("Failed to fetch user ML analysis:", err)
      setError("Failed to load ML insights")
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className={`bg-white rounded-lg shadow-lg p-6 ${className}`}>
        <div className="flex items-center justify-center py-8">
          <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-purple-600"></div>
          <span className="ml-3 text-gray-600">Loading ML insights...</span>
        </div>
      </div>
    )
  }

  if (error || !mlAnalysis) {
    return (
      <div className={`bg-white rounded-lg shadow-lg p-6 ${className}`}>
        <div className="text-center py-8">
          <AlertTriangle className="h-8 w-8 text-red-500 mx-auto mb-2" />
          <p className="text-gray-600">{error || "No ML analysis available"}</p>
        </div>
      </div>
    )
  }

  const getRiskLevelColor = (level: string) => {
    switch (level.toLowerCase()) {
      case "low":
        return "text-green-600 bg-green-100"
      case "medium":
        return "text-yellow-600 bg-yellow-100"
      case "high":
        return "text-orange-600 bg-orange-100"
      case "critical":
        return "text-red-600 bg-red-100"
      default:
        return "text-gray-600 bg-gray-100"
    }
  }

  return (
    <div className={`bg-white rounded-lg shadow-lg ${className}`}>
      {/* Header */}
      <div className="px-6 py-4 border-b border-gray-200">
        <div className="flex items-center">
          <Brain className="h-6 w-6 text-purple-600 mr-3" />
          <h3 className="text-lg font-semibold text-gray-900">ML Security Analysis</h3>
        </div>
      </div>

      <div className="p-6 space-y-6">
        {/* Risk Overview */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-gradient-to-r from-purple-50 to-purple-100 rounded-lg p-4">
            <div className="flex items-center">
              <Shield className="h-6 w-6 text-purple-600" />
              <div className="ml-3">
                <p className="text-sm font-medium text-purple-900">Risk Score</p>
                <p className="text-2xl font-bold text-purple-700">
                  {mlAnalysis.detailed_risk_analysis.risk_score.toFixed(1)}
                </p>
              </div>
            </div>
          </div>

          <div className="bg-gradient-to-r from-blue-50 to-blue-100 rounded-lg p-4">
            <div className="flex items-center">
              <Activity className="h-6 w-6 text-blue-600" />
              <div className="ml-3">
                <p className="text-sm font-medium text-blue-900">Activities Analyzed</p>
                <p className="text-2xl font-bold text-blue-700">{mlAnalysis.risk_profile.activities_analyzed}</p>
              </div>
            </div>
          </div>

          <div className="bg-gradient-to-r from-gray-50 to-gray-100 rounded-lg p-4">
            <div className="flex items-center">
              <TrendingUp className="h-6 w-6 text-gray-600" />
              <div className="ml-3">
                <p className="text-sm font-medium text-gray-900">Confidence</p>
                <p className="text-2xl font-bold text-gray-700">
                  {(mlAnalysis.detailed_risk_analysis.confidence * 100).toFixed(0)}%
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Risk Level Badge */}
        <div className="flex items-center justify-center">
          <span
            className={`px-4 py-2 rounded-full text-sm font-medium ${getRiskLevelColor(mlAnalysis.detailed_risk_analysis.risk_level)}`}
          >
            {mlAnalysis.detailed_risk_analysis.risk_level.toUpperCase()} RISK
          </span>
        </div>

        {/* Risk Factors */}
        {mlAnalysis.detailed_risk_analysis.risk_factors.length > 0 && (
          <div className="bg-red-50 rounded-lg p-4">
            <h4 className="text-md font-semibold text-red-900 mb-3 flex items-center">
              <AlertTriangle className="h-5 w-5 mr-2" />
              Risk Factors
            </h4>
            <div className="space-y-2">
              {mlAnalysis.detailed_risk_analysis.risk_factors.map((factor, index) => (
                <div key={index} className="flex items-center text-sm text-red-800">
                  <div className="w-2 h-2 bg-red-500 rounded-full mr-3"></div>
                  {factor}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Protective Factors */}
        {mlAnalysis.detailed_risk_analysis.protective_factors.length > 0 && (
          <div className="bg-green-50 rounded-lg p-4">
            <h4 className="text-md font-semibold text-green-900 mb-3 flex items-center">
              <Shield className="h-5 w-5 mr-2" />
              Protective Factors
            </h4>
            <div className="space-y-2">
              {mlAnalysis.detailed_risk_analysis.protective_factors.map((factor, index) => (
                <div key={index} className="flex items-center text-sm text-green-800">
                  <div className="w-2 h-2 bg-green-500 rounded-full mr-3"></div>
                  {factor}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ML Insights */}
        {mlAnalysis.risk_profile.insights.length > 0 && (
          <div className="bg-blue-50 rounded-lg p-4">
            <h4 className="text-md font-semibold text-blue-900 mb-3 flex items-center">
              <Brain className="h-5 w-5 mr-2" />
              ML Insights
            </h4>
            <div className="space-y-2">
              {mlAnalysis.risk_profile.insights.map((insight, index) => (
                <div key={index} className="flex items-center text-sm text-blue-800">
                  <div className="w-2 h-2 bg-blue-500 rounded-full mr-3"></div>
                  {insight}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Security Recommendations */}
        {mlAnalysis.security_recommendations.length > 0 && (
          <div className="bg-yellow-50 rounded-lg p-4">
            <h4 className="text-md font-semibold text-yellow-900 mb-3 flex items-center">
              <Shield className="h-5 w-5 mr-2" />
              Security Recommendations
            </h4>
            <div className="space-y-2">
              {mlAnalysis.security_recommendations.map((recommendation, index) => (
                <div key={index} className="flex items-center text-sm text-yellow-800">
                  <div className="w-2 h-2 bg-yellow-500 rounded-full mr-3"></div>
                  {recommendation}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
