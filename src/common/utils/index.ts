import { Coordinates, TripFareCalculation } from '../types';

/**
 * Calculate distance between two coordinates using Haversine formula
 * @param coord1 First coordinate point
 * @param coord2 Second coordinate point
 * @returns Distance in kilometers
 */
export function calculateDistance(coord1: Coordinates, coord2: Coordinates): number {
  const R = 6371; // Earth's radius in kilometers
  const dLat = toRadians(coord2.latitude - coord1.latitude);
  const dLon = toRadians(coord2.longitude - coord1.longitude);
  
  const a = 
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRadians(coord1.latitude)) * 
    Math.cos(toRadians(coord2.latitude)) * 
    Math.sin(dLon / 2) * Math.sin(dLon / 2);
  
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  const distance = R * c;
  
  return Math.round(distance * 100) / 100; // Round to 2 decimal places
}

/**
 * Convert degrees to radians
 */
function toRadians(degrees: number): number {
  return degrees * (Math.PI / 180);
}

/**
 * Calculate trip fare based on distance and duration
 * @param distance Distance in kilometers
 * @param duration Duration in minutes
 * @returns Fare calculation breakdown
 */
export function calculateTripFare(distance: number, duration: number): TripFareCalculation {
  // Yangon taxi fare structure (customizable)
  const BASE_FARE = 500; // MMK
  const RATE_PER_KM = 200; // MMK per km
  const RATE_PER_MINUTE = 15; // MMK per minute
  
  const baseFare = BASE_FARE;
  const distanceFare = distance * RATE_PER_KM;
  const timeFare = duration * RATE_PER_MINUTE;
  const totalFare = baseFare + distanceFare + timeFare;
  
  return {
    distance,
    duration,
    baseFare,
    distanceFare: Math.round(distanceFare),
    timeFare: Math.round(timeFare),
    totalFare: Math.round(totalFare),
  };
}

/**
 * Find drivers within specified radius of a location
 * @param centerPoint Center coordinates
 * @param driverLocations Array of driver locations
 * @param radiusKm Radius in kilometers
 * @returns Filtered array of nearby drivers
 */
export function findNearbyDrivers<T extends { location: Coordinates }>(
  centerPoint: Coordinates,
  driverLocations: T[],
  radiusKm: number = 5,
): T[] {
  return driverLocations.filter(driver => {
    const distance = calculateDistance(centerPoint, driver.location);
    return distance <= radiusKm;
  });
}

/**
 * Generate a random ID
 */
export function generateId(): string {
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
}

/**
 * Validate coordinates
 */
export function isValidCoordinates(coord: Coordinates): boolean {
  return (
    typeof coord.latitude === 'number' &&
    typeof coord.longitude === 'number' &&
    coord.latitude >= -90 &&
    coord.latitude <= 90 &&
    coord.longitude >= -180 &&
    coord.longitude <= 180
  );
}

/**
 * Format currency for Myanmar Kyat
 */
export function formatCurrency(amount: number): string {
  return `${amount.toLocaleString()} MMK`;
}

/**
 * Calculate duration between two dates in minutes
 */
export function calculateDurationMinutes(startDate: Date, endDate: Date): number {
  const diffMs = endDate.getTime() - startDate.getTime();
  return Math.round(diffMs / (1000 * 60));
}

/**
 * Sanitize phone number for Myanmar format
 */
export function sanitizePhoneNumber(phone: string): string {
  // Remove all non-digits
  const digits = phone.replace(/\D/g, '');
  
  // Myanmar phone numbers typically start with 09
  if (digits.startsWith('95') && digits.length === 11) {
    return '+' + digits;
  } else if (digits.startsWith('9') && digits.length === 10) {
    return '+95' + digits;
  } else if (digits.startsWith('09') && digits.length === 11) {
    return '+95' + digits.substring(1);
  }
  
  return phone; // Return original if format not recognized
}
