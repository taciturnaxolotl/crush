package dialog

import (
	"context"
	"fmt"
	"strings"
	"time"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/spinner"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/catwalk/pkg/catwalk"
	"github.com/charmbracelet/crush/internal/config"
	"github.com/charmbracelet/crush/internal/oauth"
	"github.com/charmbracelet/crush/internal/oauth/anthropic"
	"github.com/charmbracelet/crush/internal/ui/common"
	"github.com/charmbracelet/crush/internal/uiutil"
	uv "github.com/charmbracelet/ultraviolet"
	"github.com/pkg/browser"
)

// OAuthAnthropicState represents the current state of the authorization code flow.
type OAuthAnthropicState int

const (
	OAuthAnthropicStateReady OAuthAnthropicState = iota
	OAuthAnthropicStateWaitingForCode
	OAuthAnthropicStateExchanging
	OAuthAnthropicStateSuccess
	OAuthAnthropicStateError
)

// OAuthAnthropicID is the identifier for the Anthropic OAuth dialog.
const OAuthAnthropicID = "oauth-anthropic"

// OAuthAnthropic handles the Anthropic authorization code OAuth flow.
type OAuthAnthropic struct {
	com          *common.Common
	isOnboarding bool

	provider  catwalk.Provider
	model     config.SelectedModel
	modelType config.SelectedModelType

	State OAuthAnthropicState

	spinner      spinner.Model
	codeInput    textinput.Model
	help         help.Model
	keyMap       struct {
		Submit key.Binding
		Close  key.Binding
	}

	width        int
	authParams   *anthropic.AuthParams
	token        *oauth.Token
	errorMessage string
}

var _ Dialog = (*OAuthAnthropic)(nil)

// ActionAnthropicAuthInitialized is sent when auth params are ready.
type ActionAnthropicAuthInitialized struct {
	AuthParams *anthropic.AuthParams
	Error      error
}

// ActionAnthropicTokenExchanged is sent when token exchange completes.
type ActionAnthropicTokenExchanged struct {
	Token *oauth.Token
	Error error
}

// NewOAuthAnthropic creates a new Anthropic OAuth component.
func NewOAuthAnthropic(
	com *common.Common,
	isOnboarding bool,
	provider catwalk.Provider,
	model config.SelectedModel,
	modelType config.SelectedModelType,
) (*OAuthAnthropic, tea.Cmd) {
	t := com.Styles

	m := OAuthAnthropic{}
	m.com = com
	m.isOnboarding = isOnboarding
	m.provider = provider
	m.model = model
	m.modelType = modelType
	m.width = 60
	m.State = OAuthAnthropicStateReady

	m.spinner = spinner.New(
		spinner.WithSpinner(spinner.Dot),
		spinner.WithStyle(t.Base.Foreground(t.GreenLight)),
	)

	m.codeInput = textinput.New()
	m.codeInput.Placeholder = "Paste code#state here..."
	m.codeInput.SetVirtualCursor(false)
	m.codeInput.Prompt = "> "
	m.codeInput.SetStyles(t.TextInput)
	m.codeInput.SetWidth(50)

	m.help = help.New()
	m.help.Styles = t.DialogHelpStyles()

	m.keyMap.Submit = key.NewBinding(
		key.WithKeys("enter", "ctrl+y"),
		key.WithHelp("enter", "submit"),
	)
	m.keyMap.Close = CloseKey

	return &m, nil
}

// ID implements Dialog.
func (m *OAuthAnthropic) ID() string {
	return OAuthAnthropicID
}

func (m *OAuthAnthropic) initiateAuth() tea.Msg {
	authParams, err := anthropic.InitiateAuth()
	if err != nil {
		return ActionAnthropicAuthInitialized{
			AuthParams: nil,
			Error:      fmt.Errorf("failed to initiate auth: %w", err),
		}
	}

	return ActionAnthropicAuthInitialized{
		AuthParams: authParams,
		Error:      nil,
	}
}

func (m *OAuthAnthropic) exchangeCode(code, state string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		token, err := anthropic.ExchangeCode(ctx, code, m.authParams.CodeVerifier, state)
		return ActionAnthropicTokenExchanged{
			Token: token,
			Error: err,
		}
	}
}

// HandleMsg handles messages and state transitions.
func (m *OAuthAnthropic) HandleMsg(msg tea.Msg) Action {
	switch msg := msg.(type) {
	case spinner.TickMsg:
		if m.State == OAuthAnthropicStateExchanging {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			if cmd != nil {
				return ActionCmd{cmd}
			}
		}

	case tea.KeyPressMsg:
		switch {
		case key.Matches(msg, m.keyMap.Submit):
			switch m.State {
			case OAuthAnthropicStateReady:
				// Initiate OAuth flow
				return ActionCmd{
					tea.Batch(
						m.spinner.Tick,
						m.initiateAuth,
					),
				}
			case OAuthAnthropicStateWaitingForCode:
				// Check if input is empty - if so, open browser and copy URL
				if strings.TrimSpace(m.codeInput.Value()) == "" {
					if m.authParams != nil {
						return ActionCmd{
							tea.Sequence(
								tea.SetClipboard(m.authParams.AuthURL),
								func() tea.Msg {
									_ = browser.OpenURL(m.authParams.AuthURL)
									return nil
								},
								m.codeInput.Focus(),
							),
						}
					}
					return ActionCmd{m.codeInput.Focus()}
				}
				return m.submitCode()
			case OAuthAnthropicStateSuccess:
				return m.saveKeyAndContinue()
			}

		case key.Matches(msg, m.keyMap.Close):
			switch m.State {
			case OAuthAnthropicStateSuccess:
				return m.saveKeyAndContinue()
			default:
				return ActionClose{}
			}
		}

	case ActionAnthropicAuthInitialized:
		if msg.Error != nil {
			m.State = OAuthAnthropicStateError
			m.errorMessage = msg.Error.Error()
			return nil
		}
		m.authParams = msg.AuthParams
		m.State = OAuthAnthropicStateWaitingForCode
		// Copy URL to clipboard, open browser, and focus input
		return ActionCmd{
			tea.Batch(
				tea.SetClipboard(m.authParams.AuthURL),
				func() tea.Msg {
					_ = browser.OpenURL(m.authParams.AuthURL)
					return nil
				},
				m.codeInput.Focus(),
			),
		}

	case ActionAnthropicTokenExchanged:
		if msg.Error != nil {
			m.State = OAuthAnthropicStateError
			m.errorMessage = msg.Error.Error()
			return ActionCmd{uiutil.ReportError(msg.Error)}
		}
		m.token = msg.Token
		// Immediately save and return ActionSelectModel
		return m.saveKeyAndContinue()
	}

	// Update text input
	if m.State == OAuthAnthropicStateWaitingForCode {
		var cmd tea.Cmd
		m.codeInput, cmd = m.codeInput.Update(msg)
		if cmd != nil {
			return ActionCmd{cmd}
		}
	}

	return nil
}

func (m *OAuthAnthropic) submitCode() Action {
	input := strings.TrimSpace(m.codeInput.Value())
	if input == "" {
		return ActionCmd{uiutil.ReportError(fmt.Errorf("please enter the code"))}
	}

	// Parse code#state format
	if !strings.Contains(input, "#") {
		return ActionCmd{uiutil.ReportError(fmt.Errorf("invalid format: expected code#state"))}
	}

	parts := strings.SplitN(input, "#", 2)
	code := parts[0]
	state := parts[1]

	// Validate state
	if state != m.authParams.State {
		return ActionCmd{uiutil.ReportError(fmt.Errorf("state mismatch - please try again"))}
	}

	m.State = OAuthAnthropicStateExchanging
	m.codeInput.Blur()
	return ActionCmd{tea.Batch(m.spinner.Tick, m.exchangeCode(code, state))}
}

// Draw renders the dialog.
func (m *OAuthAnthropic) Draw(scr uv.Screen, area uv.Rectangle) *tea.Cursor {
	var (
		t           = m.com.Styles
		dialogStyle = t.Dialog.View.Width(m.width)
	)

	// Get cursor position for text input
	var cur *tea.Cursor
	if m.State == OAuthAnthropicStateWaitingForCode {
		cur = m.codeInput.Cursor()
		if cur != nil {
			// Add Y offset for content above the input:
			// - instructions: Margin(1,1,0,1) = 1 top margin + 1 content line = 2
			// - url: Margin(1,1,0,1) = 1 top margin + 1 content line = 2
			// - inputPrompt: Margin(1,1,0,1) = 1 top margin + 1 content line = 2
			// Total: 6 lines
			cur.Y += 6
		}
		cur = InputCursor(t, cur)
	}

	if m.isOnboarding {
		view := m.dialogContent()
		DrawOnboardingCursor(scr, area, view, cur)
		// FIXME(@andreynering): Figure it out how to properly fix this
		if cur != nil {
			cur.Y -= 1
			cur.X -= 1
		}
	} else {
		view := dialogStyle.Render(m.dialogContent())
		DrawCenterCursor(scr, area, view, cur)
	}

	return cur
}

func (m *OAuthAnthropic) dialogContent() string {
	var (
		t         = m.com.Styles
		helpStyle = t.Dialog.HelpView
	)

	elements := []string{
		m.headerContent(),
		m.innerDialogContent(),
		helpStyle.Render(m.help.View(m)),
	}
	return strings.Join(elements, "\n")
}

func (m *OAuthAnthropic) headerContent() string {
	var (
		t            = m.com.Styles
		titleStyle   = t.Dialog.Title
		textStyle    = t.Dialog.PrimaryText
		dialogStyle  = t.Dialog.View.Width(m.width)
		headerOffset = titleStyle.GetHorizontalFrameSize() + dialogStyle.GetHorizontalFrameSize()
		dialogTitle  = "Authenticate with Anthropic"
	)
	if m.isOnboarding {
		return textStyle.Render(dialogTitle)
	}
	return common.DialogTitle(t, titleStyle.Render(dialogTitle), m.width-headerOffset, t.Primary, t.Secondary)
}

func (m *OAuthAnthropic) innerDialogContent() string {
	var (
		t            = m.com.Styles
		mutedStyle   = lipgloss.NewStyle().Foreground(t.FgMuted)
		greenStyle   = lipgloss.NewStyle().Foreground(t.GreenLight)
		errorStyle   = lipgloss.NewStyle().Foreground(t.Error)
		whiteStyle   = lipgloss.NewStyle().Foreground(t.White)
		primaryStyle = lipgloss.NewStyle().Foreground(t.Primary)
	)

	switch m.State {
	case OAuthAnthropicStateReady:
		instructions := lipgloss.NewStyle().
			Margin(1, 1).
			Width(m.width - 2).
			Render(
				whiteStyle.Render("Press ") +
					primaryStyle.Render("enter") +
					whiteStyle.Render(" to open your browser and sign in with\nyour Claude account."),
			)
		return instructions

	case OAuthAnthropicStateWaitingForCode:
		instructions := lipgloss.NewStyle().
			Margin(1, 1, 0, 1).
			Width(m.width - 2).
			Render(
				whiteStyle.Render("Press ") +
					primaryStyle.Render("enter") +
					whiteStyle.Render(" to open the browser."),
			)

		url := mutedStyle.
			Margin(1, 1, 0, 1).
			Width(m.width - 2).
			Render("Browser not opening? Try pasting the link.")

		inputPrompt := whiteStyle.
			Margin(1, 1, 0, 1).
			Width(m.width - 2).
			Render("After authorizing, paste the " + primaryStyle.Inline(true).Render("code#state") + " below:")

		inputBox := t.Dialog.InputPrompt.Render(m.codeInput.View())

		return lipgloss.JoinVertical(
			lipgloss.Left,
			instructions,
			url,
			inputPrompt,
			inputBox,
		)

	case OAuthAnthropicStateExchanging:
		return lipgloss.NewStyle().
			Margin(1, 1).
			Width(m.width - 2).
			Align(lipgloss.Center).
			Render(
				greenStyle.Render(m.spinner.View()) +
					mutedStyle.Render("Exchanging code for tokens..."),
			)

	case OAuthAnthropicStateSuccess:
		return greenStyle.
			Margin(1).
			Width(m.width - 2).
			Render("Authentication successful!")

	case OAuthAnthropicStateError:
		errMsg := "Authentication failed."
		if m.errorMessage != "" {
			errMsg = fmt.Sprintf("Authentication failed: %s", m.errorMessage)
		}
		return lipgloss.NewStyle().
			Margin(1).
			Width(m.width - 2).
			Render(errorStyle.Render(errMsg))

	default:
		return ""
	}
}

// FullHelp returns the full help view.
func (m *OAuthAnthropic) FullHelp() [][]key.Binding {
	return [][]key.Binding{m.ShortHelp()}
}

// ShortHelp returns the short help view.
func (m *OAuthAnthropic) ShortHelp() []key.Binding {
	switch m.State {
	case OAuthAnthropicStateReady:
		return []key.Binding{
			key.NewBinding(
				key.WithKeys("enter", "ctrl+y"),
				key.WithHelp("enter", "open browser"),
			),
			m.keyMap.Close,
		}

	case OAuthAnthropicStateError:
		return []key.Binding{m.keyMap.Close}

	case OAuthAnthropicStateSuccess:
		return []key.Binding{
			key.NewBinding(
				key.WithKeys("enter", "ctrl+y", "esc"),
				key.WithHelp("enter", "finish"),
			),
		}

	case OAuthAnthropicStateWaitingForCode:
		return []key.Binding{
			key.NewBinding(
				key.WithKeys("enter", "ctrl+y"),
				key.WithHelp("enter", "open browser / submit"),
			),
			m.keyMap.Close,
		}

	default:
		return []key.Binding{m.keyMap.Close}
	}
}

func (m *OAuthAnthropic) saveKeyAndContinue() Action {
	cfg := m.com.Config()

	// Prefix with "Bearer " so coordinator uses Authorization header
	bearerToken := "Bearer " + m.token.AccessToken
	m.token.AccessToken = bearerToken

	err := cfg.SetProviderAPIKey(string(m.provider.ID), m.token)
	if err != nil {
		return ActionCmd{uiutil.ReportError(fmt.Errorf("failed to save API key: %w", err))}
	}

	return ActionSelectModel{
		Provider:  m.provider,
		Model:     m.model,
		ModelType: m.modelType,
	}
}
