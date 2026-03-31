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
	"charm.land/catwalk/pkg/catwalk"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/crush/internal/config"
	"github.com/charmbracelet/crush/internal/oauth"
	anthropicoauth "github.com/charmbracelet/crush/internal/oauth/anthropic"
	"github.com/charmbracelet/crush/internal/ui/common"
	"github.com/charmbracelet/crush/internal/ui/util"
	uv "github.com/charmbracelet/ultraviolet"
	"github.com/pkg/browser"
)

// OAuthAnthropicState is the state machine for the Anthropic auth-code flow.
type OAuthAnthropicState int

const (
	oauthAnthropicInput      OAuthAnthropicState = iota // tab bar + active input (main screen)
	oauthAnthropicExchanging                            // token exchange / API-key creation in flight
	oauthAnthropicDone                                  // success
	oauthAnthropicError                                 // unrecoverable error
)

// OAuthAnthropicID is the dialog identifier.
const OAuthAnthropicID = "oauth-anthropic"

// OAuthAnthropic handles the Anthropic PKCE authorization-code flow.
// It supports two paths depending on the granted scopes:
//   - user:inference present → bearer token (Claude.ai Pro/Max subscriber)
//   - otherwise → create a permanent API key via the Console API
type OAuthAnthropic struct {
	com          *common.Common
	isOnboarding bool

	provider  catwalk.Provider
	model     config.SelectedModel
	modelType config.SelectedModelType

	state        OAuthAnthropicState
	authParams   *anthropicoauth.AuthParams // non-nil once browser has been opened
	errorMessage string
	useAPIKey    bool // which tab is active

	spinner     spinner.Model
	codeInput   textinput.Model
	apiKeyInput textinput.Model
	help        help.Model
	keyMap      struct {
		Submit      key.Binding
		Close       key.Binding
		Tab         key.Binding
		OpenBrowser key.Binding
	}
	width int
}

var _ Dialog = (*OAuthAnthropic)(nil)

// msgs -------------------------------------------------------------------

type msgAnthropicAuthReady struct {
	params *anthropicoauth.AuthParams
	err    error
}

type msgAnthropicExchangeDone struct {
	// Exactly one of apiKey or oauthToken is set on success.
	apiKey     string       // Console path: permanent API key string
	oauthToken *oauth.Token // Inference path: bearer-token; store.go adds "Bearer " prefix
	err        error
}

// NewOAuthAnthropic constructs the dialog and returns it with any initial cmd.
func NewOAuthAnthropic(
	com *common.Common,
	isOnboarding bool,
	provider catwalk.Provider,
	model config.SelectedModel,
	modelType config.SelectedModelType,
) (*OAuthAnthropic, tea.Cmd) {
	t := com.Styles

	m := &OAuthAnthropic{
		com:          com,
		isOnboarding: isOnboarding,
		provider:     provider,
		model:        model,
		modelType:    modelType,
		width:        60,
		state:        oauthAnthropicInput,
	}

	innerWidth := m.width - t.Dialog.View.GetHorizontalFrameSize() - 2
	inputWidth := max(0, innerWidth-t.Dialog.InputPrompt.GetHorizontalFrameSize()-1)

	m.spinner = spinner.New(
		spinner.WithSpinner(spinner.Dot),
		spinner.WithStyle(t.Base.Foreground(t.GreenLight)),
	)

	m.codeInput = textinput.New()
	m.codeInput.Placeholder = "Paste code#state here..."
	m.codeInput.SetVirtualCursor(false)
	m.codeInput.Prompt = "> "
	m.codeInput.SetStyles(t.TextInput)
	m.codeInput.SetWidth(inputWidth)

	m.apiKeyInput = textinput.New()
	m.apiKeyInput.Placeholder = "sk-ant-..."
	m.apiKeyInput.SetVirtualCursor(false)
	m.apiKeyInput.Prompt = "> "
	m.apiKeyInput.EchoMode = textinput.EchoPassword
	m.apiKeyInput.EchoCharacter = '•'
	m.apiKeyInput.SetStyles(t.TextInput)
	m.apiKeyInput.SetWidth(inputWidth)

	m.help = help.New()
	m.help.Styles = t.DialogHelpStyles()

	m.keyMap.Submit = key.NewBinding(
		key.WithKeys("enter", "ctrl+y"),
		key.WithHelp("enter", "submit"),
	)
	m.keyMap.Close = CloseKey
	m.keyMap.Tab = key.NewBinding(
		key.WithKeys("tab", "shift+tab"),
		key.WithHelp("tab", "switch mode"),
	)
	m.keyMap.OpenBrowser = key.NewBinding(
		key.WithKeys("ctrl+o"),
		key.WithHelp("ctrl+o", "open browser"),
	)

	// Focus the OAuth input by default.
	return m, m.codeInput.Focus()
}

// ID implements Dialog.
func (m *OAuthAnthropic) ID() string { return OAuthAnthropicID }

// HandleMsg implements Dialog.
func (m *OAuthAnthropic) HandleMsg(msg tea.Msg) Action {
	switch msg := msg.(type) {
	case spinner.TickMsg:
		if m.state == oauthAnthropicExchanging {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			if cmd != nil {
				return ActionCmd{cmd}
			}
		}

	case msgAnthropicAuthReady:
		if msg.err != nil {
			m.state = oauthAnthropicError
			m.errorMessage = msg.err.Error()
			return nil
		}
		m.authParams = msg.params
		return ActionCmd{tea.Batch(
			tea.SetClipboard(m.authParams.AuthURL),
			func() tea.Msg { _ = browser.OpenURL(m.authParams.AuthURL); return nil },
		)}

	case msgAnthropicExchangeDone:
		if msg.err != nil {
			m.state = oauthAnthropicError
			m.errorMessage = msg.err.Error()
			return ActionCmd{util.ReportError(msg.err)}
		}
		m.state = oauthAnthropicDone
		return m.persist(msg)

	case tea.KeyPressMsg:
		switch {
		case key.Matches(msg, m.keyMap.Close):
			if m.state == oauthAnthropicDone {
				return ActionSelectModel{Provider: m.provider, Model: m.model, ModelType: m.modelType}
			}
			return ActionClose{}

		case key.Matches(msg, m.keyMap.Tab) && m.state == oauthAnthropicInput:
			m.useAPIKey = !m.useAPIKey
			if m.useAPIKey {
				m.codeInput.Blur()
				return ActionCmd{m.apiKeyInput.Focus()}
			}
			m.apiKeyInput.Blur()
			return ActionCmd{m.codeInput.Focus()}

		case key.Matches(msg, m.keyMap.OpenBrowser) && m.state == oauthAnthropicInput && !m.useAPIKey:
			return ActionCmd{tea.Batch(m.spinner.Tick, m.initiateAuth)}

		case key.Matches(msg, m.keyMap.Submit) && m.state == oauthAnthropicInput:
			return m.handleSubmit()

		case key.Matches(msg, m.keyMap.Submit) && m.state == oauthAnthropicDone:
			return ActionSelectModel{Provider: m.provider, Model: m.model, ModelType: m.modelType}
		}
	}

	// Forward events to the active input.
	if m.state == oauthAnthropicInput {
		if m.useAPIKey {
			var cmd tea.Cmd
			m.apiKeyInput, cmd = m.apiKeyInput.Update(msg)
			if cmd != nil {
				return ActionCmd{cmd}
			}
		} else {
			var cmd tea.Cmd
			m.codeInput, cmd = m.codeInput.Update(msg)
			if cmd != nil {
				return ActionCmd{cmd}
			}
		}
	}
	return nil
}

func (m *OAuthAnthropic) handleSubmit() Action {
	if m.useAPIKey {
		apiKey := strings.TrimSpace(m.apiKeyInput.Value())
		if apiKey == "" {
			return nil
		}
		if err := m.com.Workspace.SetProviderAPIKey(config.ScopeGlobal, string(m.provider.ID), apiKey); err != nil {
			return ActionCmd{util.ReportError(fmt.Errorf("failed to save API key: %w", err))}
		}
		m.state = oauthAnthropicDone
		return nil
	}

	// OAuth path.
	input := strings.TrimSpace(m.codeInput.Value())
	if input == "" {
		// No code yet — open/re-open browser.
		return ActionCmd{tea.Batch(m.spinner.Tick, m.initiateAuth)}
	}
	return m.submitCode(input)
}

func (m *OAuthAnthropic) submitCode(input string) Action {
	if !strings.Contains(input, "#") {
		return ActionCmd{util.ReportError(fmt.Errorf("expected code#state format"))}
	}
	if m.authParams == nil {
		return ActionCmd{util.ReportError(fmt.Errorf("auth not initiated — press enter with empty field first"))}
	}
	parts := strings.SplitN(input, "#", 2)
	code, state := parts[0], parts[1]
	if state != m.authParams.State {
		return ActionCmd{util.ReportError(fmt.Errorf("state mismatch — please try again"))}
	}
	m.state = oauthAnthropicExchanging
	m.codeInput.Blur()
	verifier := m.authParams.CodeVerifier
	return ActionCmd{tea.Batch(m.spinner.Tick, func() tea.Msg {
		return m.exchange(code, verifier, state)
	})}
}

func (m *OAuthAnthropic) initiateAuth() tea.Msg {
	params, err := anthropicoauth.InitiateAuth()
	return msgAnthropicAuthReady{params: params, err: err}
}

func (m *OAuthAnthropic) exchange(code, verifier, state string) tea.Msg {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	token, resp, err := anthropicoauth.ExchangeCode(ctx, code, verifier, state)
	if err != nil {
		return msgAnthropicExchangeDone{err: err}
	}

	if anthropicoauth.HasInferenceScope(resp.Scope) {
		return msgAnthropicExchangeDone{oauthToken: token}
	}

	apiKey, err := anthropicoauth.CreateAPIKey(ctx, token.AccessToken)
	if err != nil {
		return msgAnthropicExchangeDone{err: fmt.Errorf("create API key: %w", err)}
	}
	return msgAnthropicExchangeDone{apiKey: apiKey}
}

func (m *OAuthAnthropic) persist(msg msgAnthropicExchangeDone) Action {
	var err error
	if msg.apiKey != "" {
		err = m.com.Workspace.SetProviderAPIKey(config.ScopeGlobal, string(m.provider.ID), msg.apiKey)
	} else {
		err = m.com.Workspace.SetProviderAPIKey(config.ScopeGlobal, string(m.provider.ID), msg.oauthToken)
	}
	if err != nil {
		return ActionCmd{util.ReportError(fmt.Errorf("failed to save credentials: %w", err))}
	}
	return nil
}

// Draw implements Dialog.
func (m *OAuthAnthropic) Draw(scr uv.Screen, area uv.Rectangle) *tea.Cursor {
	t := m.com.Styles
	dialogStyle := t.Dialog.View.Width(m.width)

	var cur *tea.Cursor
	if m.state == oauthAnthropicInput {
		if m.useAPIKey {
			cur = InputCursor(t, m.apiKeyInput.Cursor())
		} else {
			cur = InputCursor(t, m.codeInput.Cursor())
		}
		if cur != nil {
			if m.useAPIKey {
				cur.Y += 4
			} else {
				cur.Y += 5 // OAuth description wraps to 2 lines
			}
		}
	}

	content := strings.Join([]string{
		m.headerView(),
		m.bodyView(),
		t.Dialog.HelpView.Render(m.help.View(m)),
	}, "\n")

	if m.isOnboarding {
		DrawOnboardingCursor(scr, area, content, cur)
		if cur != nil {
			cur.Y -= 1
			cur.X -= 1
		}
	} else {
		DrawCenterCursor(scr, area, dialogStyle.Render(content), cur)
	}
	return cur
}

func (m *OAuthAnthropic) headerView() string {
	t := m.com.Styles
	title := "Authenticate with Anthropic"
	if m.isOnboarding {
		return t.Dialog.PrimaryText.Render(title)
	}
	headerOffset := t.Dialog.Title.GetHorizontalFrameSize() + t.Dialog.View.Width(m.width).GetHorizontalFrameSize()
	return common.DialogTitle(t, t.Dialog.Title.Render(title), m.width-headerOffset, t.Primary, t.Secondary)
}

func (m *OAuthAnthropic) tabBar() string {
	t := m.com.Styles
	activeTab := lipgloss.NewStyle().
		Background(t.Primary).
		Foreground(t.White).
		Padding(0, 1)
	inactiveTab := lipgloss.NewStyle().
		Foreground(t.FgMuted).
		Padding(0, 1)
	if !m.useAPIKey {
		return activeTab.Render("Browser OAuth") + " " + inactiveTab.Render("API Key")
	}
	return inactiveTab.Render("Browser OAuth") + " " + activeTab.Render("API Key")
}

func (m *OAuthAnthropic) bodyView() string {
	t := m.com.Styles
	muted := lipgloss.NewStyle().Foreground(t.FgMuted)
	green := lipgloss.NewStyle().Foreground(t.GreenLight)
	errStyle := lipgloss.NewStyle().Foreground(t.Error)
	white := lipgloss.NewStyle().Foreground(t.White)

	pad := lipgloss.NewStyle().Margin(1, 1).Width(m.width - 2)

	switch m.state {
	case oauthAnthropicInput:
		var description, inputView string
		if !m.useAPIKey {
			if m.authParams == nil {
				description = white.Render("Press ctrl+o to open your browser. After authorizing, paste the code#state here:")
			} else {
				description = white.Render("Browser opened. Paste the code#state here (or ctrl+o to re-open):")
			}
			inputView = t.Dialog.InputPrompt.Render(m.codeInput.View())
		} else {
			description = white.Render("Paste your Anthropic API key below:")
			inputView = t.Dialog.InputPrompt.Render(m.apiKeyInput.View())
		}
		return lipgloss.JoinVertical(lipgloss.Left,
			lipgloss.NewStyle().Margin(1, 1, 0, 1).Render(m.tabBar()),
			lipgloss.NewStyle().Margin(1, 1, 0, 1).Width(m.width-2).Render(description),
			inputView,
		)

	case oauthAnthropicExchanging:
		return pad.Align(lipgloss.Center).Render(
			green.Render(m.spinner.View()) + muted.Render("Authenticating…"),
		)

	case oauthAnthropicDone:
		return t.Dialog.TitleAccent.Margin(1).Width(m.width - 2).Render("Authentication successful!")

	case oauthAnthropicError:
		msg := "Authentication failed."
		if m.errorMessage != "" {
			msg = "Authentication failed: " + m.errorMessage
		}
		return errStyle.Margin(1).Width(m.width - 2).Render(msg)
	}
	return ""
}

// ShortHelp implements key.Map.
func (m *OAuthAnthropic) ShortHelp() []key.Binding {
	switch m.state {
	case oauthAnthropicInput:
		if m.useAPIKey {
			return []key.Binding{
				key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "save")),
				m.keyMap.Tab,
				m.keyMap.Close,
			}
		}
		return []key.Binding{
			m.keyMap.OpenBrowser,
			key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "submit code")),
			m.keyMap.Tab,
			m.keyMap.Close,
		}
	case oauthAnthropicDone:
		return []key.Binding{
			key.NewBinding(key.WithKeys("enter", "esc"), key.WithHelp("enter", "finish")),
		}
	default:
		return []key.Binding{m.keyMap.Close}
	}
}

// FullHelp implements key.Map.
func (m *OAuthAnthropic) FullHelp() [][]key.Binding {
	return [][]key.Binding{m.ShortHelp()}
}
