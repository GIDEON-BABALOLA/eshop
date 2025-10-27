export class AppError extends Error {
    public readonly statusCode: number;
    public readonly isOperational: boolean;
    public readonly details?: any;
    constructor(message: string, statusCode: number, isOperational: true, details?: any){
        super(message);
        this.statusCode = statusCode;
        this.isOperational = isOperational;
        this.details = details;
        Error.captureStackTrace(this);
    }
}

// Not Found Error
export class NotFoundError extends AppError{
    constructor(message =  "Resources not found"){
        super(message, 404, true);
    }
}

// Validation Error(use for joi/zod/react-hook-form validation errors)
export class validationError extends AppError {
    constructor(message = "Invalid Request Data", details?: any){
        super(message, 400, true, details);
    }
}
// Authentication error
export class AuthError extends AppError{
    constructor(message = "Unauthorized"){
        super(message, 401, true);
    }
}
// Forbidden Error (For Insufficient Permissions)
export class ForbiddenError extends AppError{
    constructor(message = "Forbidden access"){
        super(message, 403, true);
    }
}
// Database Error (For MongoDB/Postgres Express)
export class DatabaseError extends AppError {
    constructor(message = "Database error", details?: any){
        super(message, 500, true, details);
    }
}
// Rate Limit Error (If user exceeds API Limits)
export class RateLimitError extends AppError{
    constructor(message = "Too many requests, please try again later"){
        super(message, 429, true)
    }
}
