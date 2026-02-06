package cmd

import (
	"context"
	"fmt"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/crush/internal/config"
	"github.com/charmbracelet/crush/internal/oauth/anthropic"
	"github.com/pkg/browser"
)

// Simple inline input model for code entry.
type codeInputModel struct {
	input    textinput.Model
	err      error
	code     string
	state    string
	finished bool
}

func newCodeInputModel() codeInputModel {
	ti := textinput.New()
	ti.Placeholder = "code#state"
	ti.Prompt = "> "
	ti.SetWidth(80)

	// Apply basic styling similar to the TUI
	ti.SetStyles(textinput.Styles{
		Focused: textinput.StyleState{
			Text:        lipgloss.NewStyle(),
			Placeholder: lipgloss.NewStyle().Foreground(lipgloss.Color("240")),
			Prompt:      lipgloss.NewStyle().Foreground(lipgloss.Color("170")), // Purple like the modals
		},
		Cursor: textinput.CursorStyle{
			Color: lipgloss.Color("170"), // Purple cursor
			Shape: tea.CursorBlock,
			Blink: true,
		},
	})
	ti.Focus()

	return codeInputModel{
		input: ti,
	}
}

func (m codeInputModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m codeInputModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		switch msg.String() {
		case "enter":
			// Parse code#state
			fullCode := m.input.Value()
			parts := splitOnce(fullCode, "#")
			if len(parts) != 2 {
				m.err = fmt.Errorf("invalid format: expected code#state")
				return m, tea.Quit
			}
			m.code = parts[0]
			m.state = parts[1]
			m.finished = true
			return m, tea.Quit

		case "ctrl+c", "esc":
			return m, tea.Quit
		}
	}

	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m codeInputModel) View() tea.View {
	return tea.View{Content: m.input.View()}
}

func loginAnthropicInline(cfg *config.Config, ctx context.Context) error {
	if cfg.HasConfigField("providers.anthropic.oauth") {
		fmt.Println("You are already logged in to Anthropic.")
		return nil
	}

	purpleStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("170"))

	fmt.Println(purpleStyle.Render("Initiating Anthropic OAuth flow..."))

	// Initiate auth
	authParams, err := anthropic.InitiateAuth()
	if err != nil {
		return fmt.Errorf("failed to initiate OAuth: %w", err)
	}

	// Display URL
	fmt.Println()
	fmt.Println("Press enter to open your browser and authenticate:")
	fmt.Println()

	// Green styled link
	greenLink := lipgloss.NewStyle().
		Foreground(lipgloss.Color("86")).
		Hyperlink(authParams.AuthURL, "id=anthropic").
		Render(authParams.AuthURL)
	fmt.Println(greenLink)

	waitEnter()

	// Open browser
	if err := browser.OpenURL(authParams.AuthURL); err != nil {
		fmt.Println("Could not open browser. Please open the URL manually.")
	}

	fmt.Println()
	fmt.Println("After authorizing, enter the code in the format:", lipgloss.NewStyle().Bold(true).Render("code#state"))
	fmt.Println()

	// Purple separator above input
	purpleSeparator := lipgloss.NewStyle().
		Foreground(lipgloss.Color("170")).
		Render("///////")
	fmt.Println(purpleSeparator)

	// Run the input model
	p := tea.NewProgram(newCodeInputModel())
	finalModel, err := p.Run()
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	m := finalModel.(codeInputModel)
	if m.err != nil {
		return m.err
	}
	if !m.finished {
		return fmt.Errorf("cancelled")
	}

	// Clear the separator line and the blank line above it
	fmt.Print("\033[2A\033[K\033[K")

	// Verify state matches
	if m.state != authParams.State {
		return fmt.Errorf("state mismatch - please try again")
	}

	fmt.Println()
	fmt.Println("Exchanging authorization code for token...")

	// Exchange code for token
	token, err := anthropic.ExchangeCode(ctx, m.code, authParams.CodeVerifier, authParams.State)
	if err != nil {
		return fmt.Errorf("failed to exchange code: %w", err)
	}

	// Prefix access token with "Bearer " so coordinator uses Authorization header.
	token.AccessToken = "Bearer " + token.AccessToken

	// Store token
	if err := cfg.SetProviderAPIKey("anthropic", token); err != nil {
		return fmt.Errorf("failed to save OAuth token: %w", err)
	}

	fmt.Println()
	fmt.Println("You're now authenticated with Anthropic!")
	return nil
}
