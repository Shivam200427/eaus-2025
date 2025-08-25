"use client"

import { useEffect, useRef, useState } from "react"
import { Loader } from "@googlemaps/js-api-loader"
import type * as google from "google.maps"

interface Location {
  lat: number
  lng: number
  country: string
  city: string
  risk_score: number
  timestamp: string
  is_suspicious: boolean
}

interface SecurityMapProps {
  locations: Location[]
}

export default function SecurityMap({ locations }: SecurityMapProps) {
  const mapRef = useRef<HTMLDivElement>(null)
  const [map, setMap] = useState<google.maps.Map | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const initMap = async () => {
      const apiKey = process.env.NEXT_PUBLIC_GOOGLE_MAPS_API_KEY

      if (!apiKey) {
        setError("Google Maps API key not configured")
        setLoading(false)
        return
      }

      try {
        const loader = new Loader({
          apiKey,
          version: "weekly",
          libraries: ["maps", "marker"],
        })

        const googleMaps = await loader.load()

        if (mapRef.current) {
          const mapInstance = new googleMaps.Map(mapRef.current, {
            center: { lat: 20, lng: 0 },
            zoom: 2,
            styles: [
              {
                featureType: "water",
                elementType: "geometry",
                stylers: [{ color: "#e9e9e9" }, { lightness: 17 }],
              },
              {
                featureType: "landscape",
                elementType: "geometry",
                stylers: [{ color: "#f5f5f5" }, { lightness: 20 }],
              },
            ],
          })

          setMap(mapInstance)

          // Add markers for each location
          locations.forEach((location) => {
            if (location.lat && location.lng) {
              const marker = new googleMaps.Marker({
                position: { lat: location.lat, lng: location.lng },
                map: mapInstance,
                title: `${location.city}, ${location.country}`,
                icon: {
                  path: googleMaps.SymbolPath.CIRCLE,
                  scale: location.is_suspicious ? 8 : 6,
                  fillColor: location.is_suspicious ? "#ef4444" : "#10b981",
                  fillOpacity: 0.8,
                  strokeColor: location.is_suspicious ? "#dc2626" : "#059669",
                  strokeWeight: 2,
                },
              })

              const infoWindow = new googleMaps.InfoWindow({
                content: `
                  <div class="p-2">
                    <h3 class="font-semibold text-sm">${location.city}, ${location.country}</h3>
                    <p class="text-xs text-gray-600 mt-1">
                      Risk Score: ${location.risk_score}<br>
                      Time: ${new Date(location.timestamp).toLocaleString()}<br>
                      Status: ${location.is_suspicious ? "Suspicious" : "Normal"}
                    </p>
                  </div>
                `,
              })

              marker.addListener("click", () => {
                infoWindow.open(mapInstance, marker)
              })
            }
          })
        }
      } catch (err) {
        console.error("Error loading Google Maps:", err)
        setError("Failed to load Google Maps")
      } finally {
        setLoading(false)
      }
    }

    initMap()
  }, [locations])

  if (loading) {
    return (
      <div className="h-96 bg-gray-100 rounded-lg flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-2"></div>
          <p className="text-sm text-gray-600">Loading map...</p>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="h-96 bg-gray-100 rounded-lg flex items-center justify-center">
        <div className="text-center">
          <p className="text-sm text-red-600 mb-2">{error}</p>
          <p className="text-xs text-gray-500">
            Please configure NEXT_PUBLIC_GOOGLE_MAPS_API_KEY in your environment variables
          </p>
        </div>
      </div>
    )
  }

  return (
    <div className="relative">
      <div ref={mapRef} className="h-96 w-full rounded-lg" />
      <div className="absolute top-4 right-4 bg-white p-3 rounded-lg shadow-md">
        <div className="text-xs font-medium text-gray-700 mb-2">Legend</div>
        <div className="flex items-center mb-1">
          <div className="w-3 h-3 rounded-full bg-green-500 mr-2"></div>
          <span className="text-xs text-gray-600">Normal Login</span>
        </div>
        <div className="flex items-center">
          <div className="w-3 h-3 rounded-full bg-red-500 mr-2"></div>
          <span className="text-xs text-gray-600">Suspicious Activity</span>
        </div>
      </div>
    </div>
  )
}
