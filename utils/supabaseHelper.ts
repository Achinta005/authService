// src/utils/supabaseHelper.ts
export class SupabaseHelper {
  static extractErrorMessage(error: any): string {
    if (error?.message) {
      return error.message;
    }

    if (error?.error_description) {
      return error.error_description;
    }

    return 'An error occurred';
  }

  static isAuthError(error: any): boolean {
    return error?.name === 'AuthError' || error?.__isAuthError === true;
  }

  static isNetworkError(error: any): boolean {
    return error?.message?.includes('network') || error?.message?.includes('fetch');
  }
}