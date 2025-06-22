export enum UserRole {
  DRIVER = 'driver',
  ADMIN = 'admin',
}

export enum TripStatus {
  PENDING = 'pending',
  IN_PROGRESS = 'in_progress',
  COMPLETED = 'completed',
  CANCELLED = 'cancelled',
}

export enum DriverStatus {
  OFFLINE = 'offline',
  ONLINE = 'online',
  ON_TRIP = 'on_trip',
  EMERGENCY = 'emergency',
}

export enum VehicleType {
  SEDAN = 'sedan',
  HATCHBACK = 'hatchback',
  SUV = 'suv',
  PICKUP = 'pickup',
}

export enum EmergencyType {
  ACCIDENT = 'accident',
  BREAKDOWN = 'breakdown',
  MEDICAL = 'medical',
  SECURITY = 'security',
  OTHER = 'other',
}

export enum EmergencyStatus {
  ACTIVE = 'active',
  RESOLVED = 'resolved',
  CANCELLED = 'cancelled',
}

export interface Coordinates {
  latitude: number;
  longitude: number;
}

export interface LocationData {
  coordinates: Coordinates;
  address?: string;
  timestamp: Date;
}

export interface PaginationOptions {
  page: number;
  limit: number;
}

export interface PaginatedResult<T> {
  data: T[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
  hasNext: boolean;
  hasPrev: boolean;
}

export interface JwtPayload {
  sub: string;
  email: string;
  role: UserRole;
  iat?: number;
  exp?: number;
}

export interface TripFareCalculation {
  distance: number; // in kilometers
  duration: number; // in minutes
  baseFare: number;
  distanceFare: number;
  timeFare: number;
  totalFare: number;
}
