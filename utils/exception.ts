export class BadRequestException extends Error {
  statusCode: number;

  constructor(message: string) {
    super(message);
    this.name = "BadRequestException";
    this.statusCode = 400;
    Object.setPrototypeOf(this, BadRequestException.prototype);
  }
}

export class NotFoundException extends Error {
  statusCode: number;

  constructor(message: string) {
    super(message);
    this.name = "NotFoundException";
    this.statusCode = 404;
    Object.setPrototypeOf(this, NotFoundException.prototype);
  }
}

export class UnauthorizedException extends Error {
  statusCode: number;

  constructor(message: string) {
    super(message);
    this.name = "UnauthorizedException";
    this.statusCode = 401;
    Object.setPrototypeOf(this, UnauthorizedException.prototype);
  }
}

export class ForbiddenException extends Error {
  statusCode: number;

  constructor(message: string) {
    super(message);
    this.name = "ForbiddenException";
    this.statusCode = 403;
    Object.setPrototypeOf(this, ForbiddenException.prototype);
  }
}

export class ConflictException extends Error {
  statusCode: number;

  constructor(message: string) {
    super(message);
    this.name = "ConflictException";
    this.statusCode = 409;
    Object.setPrototypeOf(this, ConflictException.prototype);
  }
}

export class InternalServerErrorException extends Error {
  statusCode: number;

  constructor(message: string) {
    super(message);
    this.name = "InternalServerErrorException";
    this.statusCode = 500;
    Object.setPrototypeOf(this, InternalServerErrorException.prototype);
  }
}
