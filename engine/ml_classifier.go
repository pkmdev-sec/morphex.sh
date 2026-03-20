package engine

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	ort "github.com/yalue/onnxruntime_go"
)

// MLPrediction holds the output of a single classification call.
type MLPrediction struct {
	Label      int     `json:"label"`
	LabelName  string  `json:"label_name"`
	Confidence float64 `json:"confidence"`
	LatencyMs  float64 `json:"latency_ms"`
}

// ModelMetadata stores metadata from the training pipeline's training_metadata.json.
type ModelMetadata struct {
	ModelName string            `json:"model_name"`
	MaxLength int               `json:"max_length"`
	Labels    map[string]string `json:"labels"`
}

// ContextClassifier wraps the DistilBERT ONNX model for secret classification.
// It supports two modes:
//   - ONNX mode: real neural inference via onnxruntime_go (when model.onnx is present)
//   - Heuristic mode: fast keyword scoring fallback (when no model file exists)
type ContextClassifier struct {
	mu       sync.RWMutex
	metadata ModelMetadata
	vocab    map[string]int32
	modelDir string
	loaded   bool

	// ONNX Runtime session — nil when no model.onnx is present.
	session *ort.AdvancedSession

	// inputIDs and inputMask are pre-allocated ONNX tensors reused across calls.
	inputIDs  *ort.Tensor[int64]
	inputMask *ort.Tensor[int64]
	output    *ort.Tensor[float32]
}

var (
	contextClassifierInstance *ContextClassifier
	contextClassifierOnce     sync.Once
	onnxEnvInitOnce           sync.Once
)

// GetClassifier returns the singleton ContextClassifier.
func GetClassifier() *ContextClassifier {
	contextClassifierOnce.Do(func() {
		contextClassifierInstance = &ContextClassifier{}
	})
	return contextClassifierInstance
}

// InitClassifier loads the vocabulary and, if model.onnx exists, initialises
// a real ONNX Runtime inference session. Call this once at startup.
func InitClassifier(modelDir string) error {
	clf := GetClassifier()
	clf.mu.Lock()
	defer clf.mu.Unlock()

	clf.modelDir = modelDir

	// ── Metadata ───────────────────────────────────────────────────────
	metaPath := filepath.Join(modelDir, "training_metadata.json")
	metaBytes, err := os.ReadFile(metaPath)
	if err != nil {
		clf.metadata = ModelMetadata{
			MaxLength: 512,
			Labels:    map[string]string{"0": "NOT_SECRET", "1": "SECRET"},
		}
	} else {
		if err := json.Unmarshal(metaBytes, &clf.metadata); err != nil {
			return fmt.Errorf("parse model metadata: %w", err)
		}
	}
	if clf.metadata.MaxLength == 0 {
		clf.metadata.MaxLength = 512
	}

	// ── Vocabulary ─────────────────────────────────────────────────────
	vocabPath := filepath.Join(modelDir, "vocab.txt")
	vocabBytes, err := os.ReadFile(vocabPath)
	if err != nil {
		return fmt.Errorf("read vocab.txt: %w", err)
	}
	clf.vocab = make(map[string]int32, 30522)
	for idx, line := range strings.Split(string(vocabBytes), "\n") {
		token := strings.TrimSpace(line)
		if token != "" {
			clf.vocab[token] = int32(idx)
		}
	}

	// ── ONNX Runtime Session ───────────────────────────────────────────
	onnxPath := filepath.Join(modelDir, "model.onnx")
	if _, err := os.Stat(onnxPath); err == nil {
		if err := clf.initONNXSession(onnxPath); err != nil {
			// Log but don't fail — fall back to heuristic mode.
			fmt.Fprintf(os.Stderr, "WARN: ONNX init failed, using heuristic fallback: %v\n", err)
		}
	}

	clf.loaded = true
	return nil
}

// initONNXSession creates the ONNX Runtime session, pre-allocates tensors,
// and warms up with a single dummy inference pass.
func (c *ContextClassifier) initONNXSession(onnxPath string) error {
	// Initialise the ORT environment exactly once across all classifiers.
	var envErr error
	onnxEnvInitOnce.Do(func() {
		envErr = ort.InitializeEnvironment()
	})
	if envErr != nil {
		return fmt.Errorf("ort.InitializeEnvironment: %w", envErr)
	}

	maxLen := int64(c.metadata.MaxLength)

	// Pre-allocate input/output tensors with the fixed shape [1, maxLen].
	inputShape := ort.NewShape(1, maxLen)

	inputIDs, err := ort.NewEmptyTensor[int64](inputShape)
	if err != nil {
		return fmt.Errorf("alloc input_ids tensor: %w", err)
	}

	inputMask, err := ort.NewEmptyTensor[int64](inputShape)
	if err != nil {
		inputIDs.Destroy()
		return fmt.Errorf("alloc attention_mask tensor: %w", err)
	}

	outputShape := ort.NewShape(1, 2)
	output, err := ort.NewEmptyTensor[float32](outputShape)
	if err != nil {
		inputIDs.Destroy()
		inputMask.Destroy()
		return fmt.Errorf("alloc output tensor: %w", err)
	}

	// Build the session with named inputs/outputs matching the exported model.
	session, err := ort.NewAdvancedSession(
		onnxPath,
		[]string{"input_ids", "attention_mask"},
		[]string{"logits"},
		[]ort.ArbitraryTensor{inputIDs, inputMask},
		[]ort.ArbitraryTensor{output},
		nil, // default session options
	)
	if err != nil {
		inputIDs.Destroy()
		inputMask.Destroy()
		output.Destroy()
		return fmt.Errorf("create ONNX session: %w", err)
	}

	c.session = session
	c.inputIDs = inputIDs
	c.inputMask = inputMask
	c.output = output

	// Warm-up inference to trigger any lazy JIT compilation inside ORT.
	_ = c.predictONNX("warm-up")
	return nil
}

// IsLoaded returns true when the classifier has a vocabulary loaded
// (heuristic and/or ONNX mode).
func (c *ContextClassifier) IsLoaded() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.loaded
}

// HasONNX returns true when real ONNX inference is available.
func (c *ContextClassifier) HasONNX() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.session != nil
}

// Destroy releases ONNX Runtime resources. Call on shutdown.
func (c *ContextClassifier) Destroy() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session != nil {
		c.session.Destroy()
		c.session = nil
	}
	if c.inputIDs != nil {
		c.inputIDs.Destroy()
		c.inputIDs = nil
	}
	if c.inputMask != nil {
		c.inputMask.Destroy()
		c.inputMask = nil
	}
	if c.output != nil {
		c.output.Destroy()
		c.output = nil
	}
}

// BuildContextWindow returns the ±contextLines around targetLine (1-based)
// with a >>> LINE N <<< marker on the target.
func BuildContextWindow(content string, targetLine int, contextLines int) string {
	lines := strings.Split(content, "\n")
	start := targetLine - 1 - contextLines
	if start < 0 {
		start = 0
	}
	end := targetLine + contextLines
	if end > len(lines) {
		end = len(lines)
	}

	var sb strings.Builder
	for i := start; i < end; i++ {
		if i == targetLine-1 {
			sb.WriteString(fmt.Sprintf(">>> LINE %d <<< ", targetLine))
		}
		sb.WriteString(lines[i])
		sb.WriteString("\n")
	}
	return strings.TrimSpace(sb.String())
}

// =========================================================================
// Predict — main entry point
// =========================================================================

// Predict classifies a context window as SECRET or NOT_SECRET.
// Routes to ONNX inference when the model is loaded, else uses the heuristic.
func (c *ContextClassifier) Predict(text string) MLPrediction {
	if !c.loaded {
		return MLPrediction{Label: -1, LabelName: "NOT_LOADED", Confidence: 0}
	}
	if c.session != nil {
		return c.predictONNX(text)
	}
	return c.predictHeuristic(text)
}

// PredictBatch classifies multiple context windows.
func (c *ContextClassifier) PredictBatch(texts []string) []MLPrediction {
	results := make([]MLPrediction, len(texts))
	for i, text := range texts {
		results[i] = c.Predict(text)
	}
	return results
}

// =========================================================================
// ONNX inference path
// =========================================================================

// predictONNX tokenizes the text, copies into the pre-allocated tensors,
// runs the ONNX session, and converts logits to a probability via softmax.
func (c *ContextClassifier) predictONNX(text string) MLPrediction {
	start := time.Now()

	ids, mask := c.tokenize(text, c.metadata.MaxLength)

	// Copy tokenized data into the pre-allocated tensor backing arrays.
	idsBuf := c.inputIDs.GetData()
	maskBuf := c.inputMask.GetData()
	copy(idsBuf, ids)
	copy(maskBuf, mask)

	// Run inference.
	if err := c.session.Run(); err != nil {
		return MLPrediction{
			Label:     -1,
			LabelName: "ONNX_ERROR",
			LatencyMs: float64(time.Since(start).Microseconds()) / 1000.0,
		}
	}

	// Read logits from the output tensor: shape [1, 2].
	outBuf := c.output.GetData()
	logit0 := float64(outBuf[0])
	logit1 := float64(outBuf[1])

	// Stable softmax.
	maxLogit := logit0
	if logit1 > maxLogit {
		maxLogit = logit1
	}
	exp0 := math.Exp(logit0 - maxLogit)
	exp1 := math.Exp(logit1 - maxLogit)
	sum := exp0 + exp1
	prob0 := exp0 / sum
	prob1 := exp1 / sum

	label := 0
	labelName := "NOT_SECRET"
	confidence := prob0
	if prob1 > prob0 {
		label = 1
		labelName = "SECRET"
		confidence = prob1
	}

	elapsed := float64(time.Since(start).Microseconds()) / 1000.0

	return MLPrediction{
		Label:      label,
		LabelName:  labelName,
		Confidence: math.Round(confidence*10000) / 10000,
		LatencyMs:  math.Round(elapsed*100) / 100,
	}
}

// =========================================================================
// Heuristic fallback
// =========================================================================

// predictHeuristic is a fast keyword-scoring classifier used when no ONNX
// model is available. It sums positive signals (credential keywords) and
// negative signals (test/example keywords) to produce a confidence score.
func (c *ContextClassifier) predictHeuristic(text string) MLPrediction {
	lower := strings.ToLower(text)
	credScore := 0.0
	for _, word := range mlCredentialSignalWords {
		if strings.Contains(lower, word) {
			credScore += 0.15
		}
	}
	for _, word := range mlAntiSignalWords {
		if strings.Contains(lower, word) {
			credScore -= 0.2
		}
	}

	label := 0
	labelName := "NOT_SECRET"
	confidence := 0.5 + credScore
	if confidence > 1.0 {
		confidence = 1.0
	}
	if confidence < 0.0 {
		confidence = 0.0
	}
	if confidence >= 0.55 {
		label = 1
		labelName = "SECRET"
	}

	return MLPrediction{
		Label:      label,
		LabelName:  labelName,
		Confidence: math.Round(confidence*10000) / 10000,
	}
}

// =========================================================================
// WordPiece tokenizer (pure Go, no CGo dependency)
// =========================================================================

func (c *ContextClassifier) tokenize(text string, maxLen int) ([]int64, []int64) {
	if maxLen <= 0 {
		maxLen = c.metadata.MaxLength
	}

	words := wordpiecePreTokenize(text)

	ids := make([]int64, 0, maxLen)
	ids = append(ids, int64(c.lookupToken("[CLS]")))

	for _, word := range words {
		subTokens := c.wordpieceEncode(strings.ToLower(word))
		for _, st := range subTokens {
			if len(ids) >= maxLen-1 {
				break
			}
			ids = append(ids, int64(st))
		}
		if len(ids) >= maxLen-1 {
			break
		}
	}
	ids = append(ids, int64(c.lookupToken("[SEP]")))

	attentionMask := make([]int64, maxLen)
	for i := 0; i < len(ids) && i < maxLen; i++ {
		attentionMask[i] = 1
	}
	for len(ids) < maxLen {
		ids = append(ids, 0)
	}

	return ids[:maxLen], attentionMask
}

func (c *ContextClassifier) lookupToken(tok string) int32 {
	if id, ok := c.vocab[tok]; ok {
		return id
	}
	if id, ok := c.vocab["[UNK]"]; ok {
		return id
	}
	return 0
}

func (c *ContextClassifier) wordpieceEncode(word string) []int32 {
	if _, ok := c.vocab[word]; ok {
		return []int32{c.vocab[word]}
	}

	tokens := make([]int32, 0, 8)
	start := 0
	for start < len(word) {
		end := len(word)
		found := false
		for end > start {
			substr := word[start:end]
			if start > 0 {
				substr = "##" + substr
			}
			if id, ok := c.vocab[substr]; ok {
				tokens = append(tokens, id)
				found = true
				start = end
				break
			}
			end--
		}
		if !found {
			tokens = append(tokens, c.lookupToken("[UNK]"))
			start++
		}
	}
	return tokens
}

func wordpiecePreTokenize(text string) []string {
	var words []string
	var current strings.Builder
	for _, r := range text {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			if current.Len() > 0 {
				words = append(words, current.String())
				current.Reset()
			}
			continue
		}
		if isPunctML(r) {
			if current.Len() > 0 {
				words = append(words, current.String())
				current.Reset()
			}
			words = append(words, string(r))
			continue
		}
		current.WriteRune(r)
	}
	if current.Len() > 0 {
		words = append(words, current.String())
	}
	return words
}

func isPunctML(r rune) bool {
	return (r >= '!' && r <= '/') || (r >= ':' && r <= '@') ||
		(r >= '[' && r <= '`') || (r >= '{' && r <= '~')
}

// =========================================================================
// Signal word lists for the heuristic
// =========================================================================

var mlCredentialSignalWords = []string{
	"password", "secret", "token", "api_key", "apikey", "access_key",
	"private_key", "auth_token", "credentials", "connection_string",
	"akia", "ghp_", "gho_", "ghs_", "sk_live_", "xoxb-", "sg.",
	"bearer", "-----begin",
}

var mlAntiSignalWords = []string{
	"test", "example", "sample", "mock", "fake", "dummy", "placeholder",
	"changeme", "todo", "fixme", "revoked", "expired", "disabled",
	"deactivated", "hash", "checksum", "digest", "uuid",
}
