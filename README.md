
#### **Improved `README.md`**

The README is now comprehensive, providing clear instructions for setup, configuration, and API usage.

```markdown
# Kilo-Taximm

Kilo-Taximm is a backend service for a taxi management platform, built with Golang, Gin, and MongoDB. This project is designed to be secure, scalable, and easy to deploy using Docker.

## About The Project

This service provides a RESTful API to manage taxi trips and handle emergency alerts from drivers. It is containerized for easy setup and deployment. Key features include:

-   **Secure by Design**: Hardened Docker image, secure environment variable handling, and input validation.
-   **Graceful Shutdown**: Ensures no data loss or orphaned connections on service termination.
-   **Modular Architecture**: Uses dependency injection and interfaces for clean, testable code.
-   **Containerized**: Runs with Docker and Docker Compose for a consistent environment.

## Getting Started

### Prerequisites

-   [Docker](https://www.docker.com/get-started)
-   [Docker Compose](https://docs.docker.com/compose/install/)

### Setup

1.  **Clone the repository:**
    ```sh
    git clone https://github.com/EthanVT97/kilo-taximm.git
    cd kilo-taximm
    ```

2.  **Create an environment file:**
    Copy the example environment file. The default values are configured to work with the `docker-compose.yml` setup.
    ```sh
    cp .env.example .env
    ```

3.  **Run the application:**
    Use Docker Compose to build and run the API and the MongoDB database.
    ```sh
    docker-compose up --build
    ```

The API will be available at `http://localhost:8080`.

## Environment Variables

The following environment variables are required to run the application. They should be placed in a `.env` file in the project root.

| Variable    | Description                                                   | Default Value                               |
| :---------- | :------------------------------------------------------------ | :------------------------------------------ |
| `MONGO_URI` | The connection string for the MongoDB database.               | `mongodb://kilo-user:a_new_secure_password@mongodb:27017/taxidb` |

## API Endpoints

### 1. Create a Taxi Trip

Records a completed taxi trip.

-   **Endpoint**: `POST /trip`
-   **Description**: Creates a new taxi trip entry in the database. All fields are required, and validation is enforced (`distance` and `fare` must be > 0, `endTime` must be after `startTime`).
-   **Request Body**:

    ```json
    {
        "driverId": "d-12345",
        "passengerId": "p-67890",
        "startTime": "2023-10-27T10:00:00Z",
        "endTime": "2023-10-27T10:15:00Z",
        "distance": 5.5,
        "fare": 15.75
    }
    ```

-   **Success Response (201 Created)**:

    ```json
    {
        "id": "653b8f2d5937171a4f7384a2",
        "driverId": "d-12345",
        "passengerId": "p-67890",
        "startTime": "2023-10-27T10:00:00Z",
        "endTime": "2023-10-27T10:15:00Z",
        "distance": 5.5,
        "fare": 15.75
    }
    ```

### 2. Create an Emergency Alert

Logs an emergency alert from a driver.

-   **Endpoint**: `POST /emergency`
-   **Description**: Creates an emergency log entry. Useful for tracking driver distress signals.
-   **Request Body**:

    ```json
    {
        "driverId": "d-12345",
        "location": {
            "type": "Point",
            "coordinates": [-74.0060, 40.7128]
        },
        "message": "Engine failure on 5th Ave"
    }
    ```

-   **Success Response (201 Created)**:

    ```json
    {
        "id": "653b901a5937171a4f7384a3",
        "driverId": "d-12345",
        "location": {
            "type": "Point",
            "coordinates": [-74.0060, 40.7128]
        },
        "message": "Engine failure on 5th Ave",
        "timestamp": "2023-10-27T12:30:50.123Z"
    }
    ```
