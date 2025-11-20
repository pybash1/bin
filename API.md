# `bin` API Documentation

This document provides a detailed description of the `bin` API, designed for easy comprehension by developers and large language models (LLMs).

## Overview

`bin` is a minimalist pastebin service modified for Board. It allows users to store and share snippets of text. The API is designed to be simple and straightforward.

## Authentication & Authorization

- **Device-centric Storage**: The API uses a `Device-Code` header to associate pastes with a specific device. Each device has its own separate storage space.
- **Optional Password**: The application can be configured to require an `App-Password` header for all endpoints that modify data or retrieve sensitive information.

## Headers

### `Device-Code` (Required for most endpoints)

- **Description**: An 8-character alphanumeric string that uniquely identifies the client device. This code is used to retrieve pastes created by that same device.
- **Example**: `Device-Code: A1B2C3D4`

### `App-Password` (Optional)

- **Description**: If the server is configured with a password, this header must be sent with the correct password to access protected endpoints.
- **Example**: `App-Password: your-secret-password`

---

## Endpoints

### `GET /`

- **Description**: Retrieves basic information about the API, including a list of all available endpoints.
- **Method**: `GET`
- **Path**: `/`
- **Headers**: None.
- **Success Response**:
  - **Code**: `200 OK`
  - **Content**: A JSON object describing the API.
  ```json
  {
    "message": "Bin(modified for Board)",
    "endpoints": [
      { "method": "GET", "path": "/", "description": "Get API information" },
      { "method": "POST", "path": "/", "description": "Create a new paste (form data)" },
      { "method": "PUT", "path": "/", "description": "Create a new paste (raw data)" },
      { "method": "POST", "path": "/device", "description": "Generate a unique device code" },
      { "method": "GET", "path": "/all", "description": "Get all paste IDs for your device" },
      { "method": "GET", "path": "/{paste}", "description": "Get paste content by ID" }
    ]
  }
  ```

### `POST /device`

- **Description**: Generates a new, unique `Device-Code` for a client.
- **Method**: `POST`
- **Path**: `/device`
- **Headers**:
  - `App-Password` (optional)
- **Success Response**:
  - **Code**: `200 OK`
  - **Content**: A plain text string representing the new 8-character alphanumeric device code.
- **Error Responses**:
  - `401 Unauthorized`: If the `App-Password` is required and is missing or incorrect.

### `GET /all`

- **Description**: Retrieves a list of all paste IDs associated with a given `Device-Code`.
- **Method**: `GET`
- **Path**: `/all`
- **Headers**:
  - `Device-Code` (required)
  - `App-Password` (optional)
- **Success Response**:
  - **Code**: `200 OK`
  - **Content**: A JSON array of strings, where each string is a paste ID.
  ```json
  [ "pasteId1", "pasteId2" ]
  ```
- **Error Responses**:
  - `400 Bad Request`: If the `Device-Code` header is missing or invalid.
  - `401 Unauthorized`: If the `App-Password` is required and is missing or incorrect.

### `POST /` (Form Data)

- **Description**: Creates a new paste using `application/x-www-form-urlencoded` data.
- **Method**: `POST`
- **Path**: `/`
- **Headers**:
  - `Device-Code` (required)
  - `App-Password` (optional)
- **Body**:
  - **Content-Type**: `application/x-www-form-urlencoded`
  - **Field**: `val` - The content of the paste.
- **Success Response**:
  - **Code**: `302 Found`
  - **Headers**:
    - `Location`: `/{paste_id}` - Redirects the client to the newly created paste.
- **Error Responses**:
  - `400 Bad Request`: If the `Device-Code` header is missing or invalid.
  - `401 Unauthorized`: If the `App-Password` is required and is missing or incorrect.
  - `413 Payload Too Large`: If the paste content exceeds the server's configured `max_paste_size`.

### `PUT /` (Raw Data)

- **Description**: Creates a new paste from a raw request body. This is the preferred method for programmatic clients like `curl`.
- **Method**: `PUT`
- **Path**: `/`
- **Headers**:
  - `Device-Code` (required)
  - `App-Password` (optional)
- **Body**: The raw text content of the paste.
- **Success Response**:
  - **Code**: `200 OK`
  - **Content**: A plain text string containing the full URL of the newly created paste.
  ```
  https://your-domain.com/pasteId
  ```
- **Error Responses**:
  - `400 Bad Request`: If the `Device-Code` header is missing or invalid.
  - `401 Unauthorized`: If the `App-Password` is required and is missing or incorrect.
  - `413 Payload Too Large`: If the paste content exceeds the server's configured `max_paste_size`.

### `GET /{paste}`

- **Description**: Retrieves the content of a specific paste. Access is restricted to the device that created it.
- **Method**: `GET`
- **Path**: `/{paste}`
- **Path Parameters**:
  - `paste`: The ID of the paste to retrieve. If the ID includes a file extension for syntax highlighting (e.g., `pasteId.rs`), it will be handled correctly.
- **Headers**:
  - `Device-Code` (required)
  - `App-Password` (optional)
- **Success Response**:
  - **Code**: `200 OK`
  - **Content-Type**: `text/plain; charset=utf-8`
  - **Body**: The raw content of the paste.
- **Error Responses**:
  - `400 Bad Request`: If the `Device-Code` header is missing or invalid.
  - `401 Unauthorized`: If the `Device-Code` does not match the one that created the paste, or if the `App-Password` is incorrect.
  - `404 Not Found`: If no paste with the given ID exists.
