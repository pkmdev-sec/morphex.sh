package engine
import "testing"
func TestRedisExtract(t *testing.T) {
  content := `REDIS_URL = "redis://:pKGytvukFhF4vTYYojmLVOkV@redis.internal.example.com:6379/0"`
  tokens := ExtractTokens("test.py", content)
  for _, tok := range tokens {
    t.Logf("var=%s val=%s", tok.VarName, tok.Value)
  }
  if len(tokens) == 0 { t.Error("no tokens found") }
}
func TestDockerComposeExtract(t *testing.T) {
  content := "      - AWS_ACCESS_KEY_ID=AKIACVS4F8CGVYIE6IVW"
  tokens := ExtractTokens("docker-compose.yml", content)
  for _, tok := range tokens { t.Logf("var=%s val=%s", tok.VarName, tok.Value) }
  if len(tokens) == 0 { t.Error("no tokens found") }
}
func TestDockerfileExtract(t *testing.T) {
  content := "ENV GITHUB_TOKEN=ghp_SV2ceN59UAgN2BR4cXsxjGJXke1Mo4iCppaX"
  tokens := ExtractTokens("Dockerfile", content)
  for _, tok := range tokens { t.Logf("var=%s val=%s", tok.VarName, tok.Value) }
  if len(tokens) == 0 { t.Error("no tokens found") }
}
func TestGoFuncArgExtract(t *testing.T) {
  content := `credentials.NewStaticCredentials("AKIAKTAKPUXQPHR62GDS", "Ov0WRombpE2eAOmSFpPaWXgBl9Hdp2DZQ+M85NUG", "")`
  tokens := ExtractTokens("main.go", content)
  for _, tok := range tokens { t.Logf("var=%s val=%s", tok.VarName, tok.Value) }
  if len(tokens) == 0 { t.Error("no tokens found") }
}
func TestNpmrcExtract(t *testing.T) {
  content := "//registry.npmjs.org/:_authToken=npm_pepgaxT82ExHgD1OQke0st7ekxTH3fKMDb6k"
  tokens := ExtractTokens(".npmrc", content)
  for _, tok := range tokens { t.Logf("var=%s val=%s", tok.VarName, tok.Value) }
  if len(tokens) == 0 { t.Error("no tokens found") }
}
func TestCsConnStringExtract(t *testing.T) {
  content := `"Server=sql.prod.internal;Database=Orders;User Id=sa;Password=8i54tI6ht2TV2zzB;"`
  tokens := ExtractTokens("Context.cs", content)
  for _, tok := range tokens { t.Logf("var=%s val=%s", tok.VarName, tok.Value) }
  if len(tokens) == 0 { t.Error("no tokens found") }
}
func TestUrlEmbeddedTokenExtract(t *testing.T) {
  content := "git remote set-url origin https://ghp_lRJoWcURYxPY8EcFK12BGCSzOjD8uQO001xt@github.com/myorg/myrepo.git"
  tokens := ExtractTokens("ci.yml", content)
  for _, tok := range tokens { t.Logf("var=%s val=%s", tok.VarName, tok.Value) }
  if len(tokens) == 0 { t.Error("no tokens found") }
}
