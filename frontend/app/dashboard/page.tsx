"use client"

import { useAuth } from "@/contexts/AuthContext"
import { useRouter } from "next/navigation"
import { useEffect, useState } from "react"
import axios from "axios"
import { LogOut, Shield, Activity, MapPin, Brain } from "lucide-react"
import { UserMLInsights } from "@/components/UserMLInsights"

interface UserActivity {
  id: string
  ip_address: string
  location: {
    country: string
    city: string
    latitude: number
    longitude: number
  }
  timestamp: string
  is_suspicious: boolean
  risk_score: number
  user_agent: string
  ml_anomaly_score?: number
  ml_risk_prediction?: string
  behavioral_score?: number
}

interface MLInsights {
  overall_risk_level: string
  behavioral_consistency: number
  anomaly_trend: string
  risk_factors: string[]
  recommendations: string[]
}

export default function Dashboard() {
  const { user, logout, loading } = useAuth()
  const router = useRouter()
  const [activities, setActivities] = useState<UserActivity[]>([])
  const [loadingActivities, setLoadingActivities] = useState(true)
  const [mlInsights, setMlInsights] = useState<MLInsights | null>(null)
  const [loadingML, setLoadingML] = useState(true)

  useEffect(() => {
    if (!loading && !user) {
      router.push("/")
    } else if (user) {
      fetchUserActivities()
      fetchMLInsights()
    }
  }, [user, loading, router])

  const fetchUserActivities = async () => {
    try {
      const response = await axios.get(`/api/analytics/user-activity/${user?.id}`)
      setActivities(response.data.activities)
    } catch (error) {
      console.error("Failed to fetch activities:", error)
    } finally {
      setLoadingActivities(false)
    }
  }

  const fetchMLInsights = async () => {
    try {
      const response = await axios.get(`/api/ml/user-profile/${user?.id}`)
      setMlInsights(response.data)
    } catch (error) {
      console.error("Failed to fetch ML insights:", error)
    } finally {
      setLoadingML(false)
    }
  }

  if (loading || !user) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center">
              <Shield className="h-8 w-8 text-blue-600 mr-3" />
              <h1 className="text-xl font-semibold text-gray-900">User Dashboard</h1>
            </div>
            <div className="flex items-center space-x-4">
              <span className="text-sm text-gray-700">Welcome, {user.name || user.email}</span>
              {(user.role === "admin" || user.role === "super_admin") && (
                <button
                  onClick={() => router.push("/admin/dashboard")}
                  className="bg-blue-600 text-white px-4 py-2 rounded-md text-sm hover:bg-blue-700"
                >
                  Admin Panel
                </button>
              )}
              <button onClick={logout} className="flex items-center text-gray-700 hover:text-gray-900">
                <LogOut className="h-4 w-4 mr-1" />
                Logout
              </button>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <div className="bg-white overflow-hidden shadow rounded-lg">
              <div className="p-5">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <Activity className="h-6 w-6 text-blue-600" />
                  </div>
                  <div className="ml-5 w-0 flex-1">
                    <dl>
                      <dt className="text-sm font-medium text-gray-500 truncate">Total Logins</dt>
                      <dd className="text-lg font-medium text-gray-900">{activities.length}</dd>
                    </dl>
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-white overflow-hidden shadow rounded-lg">
              <div className="p-5">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <Shield className="h-6 w-6 text-yellow-600" />
                  </div>
                  <div className="ml-5 w-0 flex-1">
                    <dl>
                      <dt className="text-sm font-medium text-gray-500 truncate">Suspicious Activities</dt>
                      <dd className="text-lg font-medium text-gray-900">
                        {activities.filter((a) => a.is_suspicious).length}
                      </dd>
                    </dl>
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-white overflow-hidden shadow rounded-lg">
              <div className="p-5">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <MapPin className="h-6 w-6 text-green-600" />
                  </div>
                  <div className="ml-5 w-0 flex-1">
                    <dl>
                      <dt className="text-sm font-medium text-gray-500 truncate">Countries</dt>
                      <dd className="text-lg font-medium text-gray-900">
                        {new Set(activities.map((a) => a.location?.country)).size}
                      </dd>
                    </dl>
                  </div>
                </div>
              </div>
            </div>

            <div className="bg-white overflow-hidden shadow rounded-lg">
              <div className="p-5">
                <div className="flex items-center">
                  <div className="flex-shrink-0">
                    <Brain className="h-6 w-6 text-purple-600" />
                  </div>
                  <div className="ml-5 w-0 flex-1">
                    <dl>
                      <dt className="text-sm font-medium text-gray-500 truncate">AI Risk Level</dt>
                      <dd
                        className={`text-lg font-medium ${
                          mlInsights?.overall_risk_level === "high"
                            ? "text-red-600"
                            : mlInsights?.overall_risk_level === "medium"
                              ? "text-yellow-600"
                              : "text-green-600"
                        }`}
                      >
                        {loadingML ? "..." : mlInsights?.overall_risk_level?.toUpperCase() || "LOW"}
                      </dd>
                    </dl>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="mb-8">
            <UserMLInsights userId={user.id} />
          </div>

          <div className="bg-white shadow overflow-hidden sm:rounded-md">
            <div className="px-4 py-5 sm:px-6">
              <h3 className="text-lg leading-6 font-medium text-gray-900">Recent Login Activity</h3>
              <p className="mt-1 max-w-2xl text-sm text-gray-500">
                Your recent login sessions with AI-powered security analysis.
              </p>
            </div>
            <ul className="divide-y divide-gray-200">
              {loadingActivities ? (
                <li className="px-4 py-4">
                  <div className="animate-pulse flex space-x-4">
                    <div className="rounded-full bg-gray-300 h-10 w-10"></div>
                    <div className="flex-1 space-y-2 py-1">
                      <div className="h-4 bg-gray-300 rounded w-3/4"></div>
                      <div className="h-4 bg-gray-300 rounded w-1/2"></div>
                    </div>
                  </div>
                </li>
              ) : activities.length === 0 ? (
                <li className="px-4 py-4 text-center text-gray-500">No login activities found.</li>
              ) : (
                activities.map((activity) => (
                  <li key={activity.id} className="px-4 py-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center">
                        <div
                          className={`flex-shrink-0 h-3 w-3 rounded-full ${
                            activity.is_suspicious ? "bg-red-400" : "bg-green-400"
                          }`}
                        ></div>
                        <div className="ml-4">
                          <div className="text-sm font-medium text-gray-900">
                            {activity.location?.city}, {activity.location?.country}
                          </div>
                          <div className="text-sm text-gray-500">
                            IP: {activity.ip_address} • Risk Score: {activity.risk_score}
                            {activity.ml_anomaly_score && (
                              <> • ML Anomaly: {(activity.ml_anomaly_score * 100).toFixed(1)}%</>
                            )}
                          </div>
                        </div>
                      </div>
                      <div className="text-sm text-gray-500">{new Date(activity.timestamp).toLocaleString()}</div>
                    </div>
                    {activity.is_suspicious && (
                      <div className="mt-2 ml-7">
                        <div className="bg-red-50 border border-red-200 rounded-md p-3">
                          <div className="flex">
                            <Shield className="h-5 w-5 text-red-400" />
                            <div className="ml-3">
                              <h4 className="text-sm font-medium text-red-800">
                                {activity.ml_risk_prediction
                                  ? "AI-Detected Suspicious Activity"
                                  : "Suspicious Activity Detected"}
                              </h4>
                              <p className="text-sm text-red-700 mt-1">
                                {activity.ml_risk_prediction
                                  ? `AI Analysis: ${activity.ml_risk_prediction}. Please verify if this was you.`
                                  : "This login showed unusual patterns. Please verify if this was you."}
                              </p>
                            </div>
                          </div>
                        </div>
                      </div>
                    )}
                  </li>
                ))
              )}
            </ul>
          </div>
        </div>
      </div>
    </div>
  )
}
