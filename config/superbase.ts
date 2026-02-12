import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { config } from './env';

// Admin client with service role key (bypass RLS)
export const supabaseAdmin: SupabaseClient = createClient(
  config.supabase.url,
  config.supabase.serviceRoleKey,
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
  }
);

// Public client with anon key (respects RLS)
export const supabaseClient: SupabaseClient = createClient(
  config.supabase.url,
  config.supabase.anonKey
);

console.log('✅ Supabase clients initialized');