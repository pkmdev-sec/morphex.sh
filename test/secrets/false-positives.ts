// Test: These should NOT be flagged as secrets
const API_KEY = process.env.API_KEY;
const DB_PASSWORD = "${DATABASE_PASSWORD}";
const CONFIG_PATH = "/etc/myapp/config.yaml";
const PLACEHOLDER = "your_api_key_here";
const EXAMPLE_KEY = "AKIAIOSFODNN7EXAMPLE";
const TEST_KEY = "sk_test_4eC39HqLyjWDarjtT1zdp7dc";
const IMAGE = "018537234677.dkr.ecr.us-east-1.amazonaws.com/myapp:latest";
const K8S_GROUP = "rbac.authorization.k8s.io";
const CONSTANT_REF: string = "SUBSCRIPTION_SID_KEY";
