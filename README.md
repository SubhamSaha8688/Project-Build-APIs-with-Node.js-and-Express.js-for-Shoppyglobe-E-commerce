# Project-Build-APIs-with-Node.js-and-Express.js-for-Shoppyglobe-E-commerce

https://github.com/SubhamSaha8688/Project-Build-APIs-with-Node.js-and-Express.js-for-Shoppyglobe-E-commerce.git

A complete backend API for ShoppyGlobe e-commerce application built with Node.js, Express, and MongoDB.

## Features

- User authentication with JWT (register and login)
- Product management (listing and details)
- Shopping cart functionality (add, update, delete items)
- Error handling and input validation
- MongoDB integration
- Protected routes

## Technologies Used

- Node.js
- Express.js
- MongoDB (with Mongoose)
- JSON Web Tokens (JWT)
- bcrypt.js (for password hashing)
- Express Rate Limit (for API rate limiting)

## Prerequisites

- Node.js (v14 or higher)
- MongoDB Compass
- ThunderClient or similar API testing tool

## Installation

1. Clone the repository
2. Install dependencies:
   ```
   npm install
   ```
3. Create a `.env` file in the root directory with the following variables:
   ```
   PORT=5000
   JWT_SECRET=your_jwt_secret
   ```
4. Make sure MongoDB is running on your local machine at `mongodb://localhost:27017`

## Running the Application

Start the server in development mode:
```
npm run dev
```

Or in production mode:
```
npm start
```

The server will start on port 5000 by default (or the port specified in your `.env` file).

## API Documentation

### Authentication Routes

#### Register a New User
- **URL**: `/register`
- **Method**: `POST`
- **Body**:
  ```json
  {
    "username": "user123",
    "email": "user@example.com",
    "password": "password123"
  }
  ```
- **Response**:
  ```json
  {
    "message": "User registered successfully",
    "token": "jwt_token_here",
    "user": {
      "id": "user_id",
      "username": "user123",
      "email": "user@example.com"
    }
  }
  ```

#### Login
- **URL**: `/login`
- **Method**: `POST`
- **Body**:
  ```json
  {
    "email": "user@example.com",
    "password": "password123"
  }
  ```
- **Response**:
  ```json
  {
    "message": "Login successful",
    "token": "jwt_token_here",
    "user": {
      "id": "user_id",
      "username": "user123",
      "email": "user@example.com"
    }
  }
  ```

### Product Routes

#### Get All Products
- **URL**: `/products`
- **Method**: `GET`
- **Response**: Array of products with format:
  ```json
  [
    {
      "id": 1,
      "title": "Product Name",
      "description": "Product description",
      "category": "Category",
      "price": 99.99,
      "rating": 4.5,
      "stock": 100
    }
  ]
  ```

#### Get Product by ID
- **URL**: `/products/:id`
- **Method**: `GET`
- **Response**: Single product object

#### Create Product
- **URL**: `/products`
- **Method**: `POST`
- **Body**:
  ```json
  {
    "title": "Product Name",
    "description": "Product description",
    "category": "Category",
    "price": 99.99,
    "rating": 4.5,
    "stock": 100
  }
  ```
- **Response**: Created product object

### Cart Routes (Protected - Requires Authentication)

#### Get User's Cart
- **URL**: `/cart`
- **Method**: `GET`
- **Headers**: `Authorization: Bearer jwt_token_here`
- **Response**: Array of cart items

#### Add Product to Cart
- **URL**: `/cart`
- **Method**: `POST`
- **Headers**: `Authorization: Bearer jwt_token_here`
- **Body**:
  ```json
  {
    "productId": 1,
    "quantity": 2
  }
  ```
- **Response**:
  ```json
  {
    "message": "Product added to cart",
    "cartItem": {
      "_id": "cart_item_id",
      "user": "user_id",
      "product": {
        "id": 1,
        "title": "Product Name",
        "description": "Product description",
        "category": "Category",
        "price": 99.99,
        "rating": 4.5,
        "stock": 100
      },
      "quantity": 2,
      "addedAt": "date_time"
    }
  }
  ```

#### Update Cart Item Quantity
- **URL**: `/cart/:id`
- **Method**: `PUT`
- **Headers**: `Authorization: Bearer jwt_token_here`
- **Body**:
  ```json
  {
    "quantity": 3
  }
  ```
- **Response**: Updated cart item

#### Remove Item from Cart
- **URL**: `/cart/:id`
- **Method**: `DELETE`
- **Headers**: `Authorization: Bearer jwt_token_here`
- **Response**:
  ```json
  {
    "message": "Item removed from cart"
  }
  ```

## Testing with ThunderClient

1. Register a new user
   - Send a POST request to `/register` with user details
   - Save the returned JWT token

2. Login with the registered user
   - Send a POST request to `/login` with credentials
   - Save the returned JWT token

3. Create some test products
   - Send POST requests to `/products` with product details
   - Example product:
     ```json
     {
       "title": "Smartphone",
       "description": "Latest model smartphone",
       "category": "Electronics",
       "price": 999.99,
       "rating": 4.5,
       "stock": 50
     }
     ```

4. List all products
   - Send a GET request to `/products`

5. Get a single product
   - Send a GET request to `/products/:id` using an ID from the list

6. Add products to cart
   - Send a POST request to `/cart` with product ID and quantity
   - Include JWT token in Authorization header

7. View cart
   - Send a GET request to `/cart`
   - Include JWT token in Authorization header

8. Update cart item quantity
   - Send a PUT request to `/cart/:id` with new quantity
   - Include JWT token in Authorization header

9. Remove item from cart
   - Send a DELETE request to `/cart/:id`
   - Include JWT token in Authorization header

## Error Handling

The API includes comprehensive error handling for:
- Invalid input data
- Authentication failures
- Database errors
- Resource not found errors
- Authorization errors

## Security Features

- Password hashing using bcrypt
- JWT authentication for protected routes
- Input validation
- Rate limiting to prevent abuse
- Proper error handling to avoid leaking sensitive information

## Project Structure

```
.
├── .env                # Environment variables
├── package.json        # Project dependencies and scripts
├── README.md          # Documentation
└── server.js          # Main application file with all routes and logic
```