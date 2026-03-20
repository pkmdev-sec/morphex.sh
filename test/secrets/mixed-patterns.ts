// Test: Mix of real secrets and safe patterns
import { config } from "./config";

// REAL - should be caught
const TWILIO_AUTH = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
const signing_key = "VWdFs2SseeFzETVh9kMpQr";

// SAFE - should NOT be caught  
const endpoint = "https://api.twilio.com/v1/accounts";
const vault_ref = "vault:secret/data/myapp#token";
const helm_value = "{{ .Values.secretName }}";
const ssm_param = "ssm:/prod/db-password";
