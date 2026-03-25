package api

import (
	"github.com/gofiber/fiber/v2"
)

type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ChatRequest struct {
	Message string        `json:"message"`
	History []ChatMessage `json:"history"`
}

func ChatWithAI(c *fiber.Ctx) error {
	var req ChatRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request"})
	}

	if req.Message == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Message is required"})
	}

	// Get AI settings from DB
	aiProvider := getSetting("ai_provider")
	aiAPIKey := getSetting("ai_api_key")
	aiModel := getSetting("ai_model")
	aiBaseURL := getSetting("ai_base_url")

	if aiAPIKey == "" {
		return c.Status(400).JSON(fiber.Map{"error": "AI API key not configured. Contact admin to configure AI settings."})
	}

	if aiProvider == "" {
		aiProvider = "deepseek"
	}
	if aiModel == "" {
		switch aiProvider {
		case "deepseek":
			aiModel = "deepseek-chat"
		case "openai":
			aiModel = "gpt-4o-mini"
		case "anthropic":
			aiModel = "claude-sonnet-4-6-20250514"
		case "google":
			aiModel = "gemini-2.0-flash"
		default:
			aiModel = "deepseek-chat"
		}
	}
	if aiBaseURL == "" {
		switch aiProvider {
		case "deepseek":
			aiBaseURL = "https://api.deepseek.com/v1"
		case "openai":
			aiBaseURL = "https://api.openai.com/v1"
		case "anthropic":
			aiBaseURL = "https://api.anthropic.com/v1"
		case "google":
			aiBaseURL = "https://generativelanguage.googleapis.com/v1beta"
		default:
			aiBaseURL = "https://api.deepseek.com/v1"
		}
	}

	// Build messages for the AI API
	systemPrompt := `You are a cybersecurity expert assistant for Seku, a security scanning platform for websites.

Your role:
- Help users understand their scan results and security vulnerabilities
- Provide actionable advice on fixing security issues
- Explain security concepts in clear, accessible language
- Guide users on how to improve their website security scores
- Answer questions about web security best practices, headers, TLS, CSP, HSTS, etc.

Important guidelines:
- Answer in the same language as the user's message (Arabic or English)
- Be specific and technical when giving fix instructions - include config examples
- When discussing scores, remember Seku uses a 1000-point scoring system
- Reference common web servers (Apache, Nginx, IIS) when giving configuration examples
- Keep responses focused and well-structured using markdown formatting`

	// Build the messages array for the API call
	messages := []map[string]string{
		{
			"role":    "system",
			"content": systemPrompt,
		},
	}

	// Add conversation history (last 10 messages)
	for _, msg := range req.History {
		if msg.Role == "user" || msg.Role == "assistant" {
			messages = append(messages, map[string]string{
				"role":    msg.Role,
				"content": msg.Content,
			})
		}
	}

	// Add the current user message if not already in history
	if len(req.History) == 0 || req.History[len(req.History)-1].Content != req.Message {
		messages = append(messages, map[string]string{
			"role":    "user",
			"content": req.Message,
		})
	}

	// Call AI API using the existing callAIChatAPI pattern but with custom messages
	response, err := callAIChatAPI(aiBaseURL, aiAPIKey, aiModel, aiProvider, messages)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "AI request failed: " + err.Error()})
	}

	return c.JSON(fiber.Map{"response": response})
}
