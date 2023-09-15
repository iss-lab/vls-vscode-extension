export class VLSError extends Error {
    statusCode = 400;
  
    constructor(message: string) {
      super(message);
  
      // 👇️ because we are extending a built-in class
      Object.setPrototypeOf(this, VLSError.prototype);
    }
  
    getErrorMessage() {
      return this.message;
    }
  }