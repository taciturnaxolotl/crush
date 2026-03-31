package cmd

import (
	"bufio"
	"cmp"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/atotto/clipboard"
	"github.com/charmbracelet/crush/internal/client"
	"github.com/charmbracelet/crush/internal/config"
	"github.com/charmbracelet/crush/internal/oauth"
	anthropicOAuth "github.com/charmbracelet/crush/internal/oauth/anthropic"
	"github.com/charmbracelet/crush/internal/oauth/copilot"
	"github.com/charmbracelet/crush/internal/oauth/hyper"
	"github.com/charmbracelet/x/ansi"
	"github.com/pkg/browser"
	"github.com/spf13/cobra"
)

var loginCmd = &cobra.Command{
	Aliases: []string{"auth"},
	Use:     "login [platform]",
	Short:   "Login Crush to a platform",
	Long: `Login Crush to a specified platform.
The platform should be provided as an argument.
Available platforms are: anthropic, hyper, copilot.`,
	Example: `
# Authenticate with Anthropic (Claude.ai Pro/Max or Console)
crush login anthropic

# Authenticate with Charm Hyper
crush login

# Authenticate with GitHub Copilot
crush login copilot
  `,
	ValidArgs: []cobra.Completion{
		"anthropic",
		"hyper",
		"copilot",
		"github",
		"github-copilot",
	},
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		c, ws, cleanup, err := connectToServer(cmd)
		if err != nil {
			return err
		}
		defer cleanup()

		progressEnabled := ws.Config.Options.Progress == nil || *ws.Config.Options.Progress
		if progressEnabled && supportsProgressBar() {
			_, _ = fmt.Fprintf(os.Stderr, ansi.SetIndeterminateProgressBar)
			defer func() { _, _ = fmt.Fprintf(os.Stderr, ansi.ResetProgressBar) }()
		}

		provider := "hyper"
		if len(args) > 0 {
			provider = args[0]
		}
		switch provider {
		case "anthropic":
			return loginAnthropic(cmd.Context(), c, ws.ID)
		case "hyper":
			return loginHyper(c, ws.ID)
		case "copilot", "github", "github-copilot":
			return loginCopilot(cmd.Context(), c, ws.ID)
		default:
			return fmt.Errorf("unknown platform: %s", args[0])
		}
	},
}

func loginAnthropic(ctx context.Context, c *client.Client, wsID string) error {
	loginCtx := getLoginContext()

	params, err := anthropicOAuth.InitiateAuth()
	if err != nil {
		return fmt.Errorf("failed to initiate auth: %w", err)
	}

	if clipboard.WriteAll(params.AuthURL) == nil {
		fmt.Println("Authorization URL copied to clipboard.")
	}
	fmt.Println()
	fmt.Println("Press enter to open the browser, or manually open this URL:")
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Hyperlink(params.AuthURL, "id=anthropic-oauth").Render(params.AuthURL))
	fmt.Println()
	waitEnter()
	if err := browser.OpenURL(params.AuthURL); err != nil {
		fmt.Println("Could not open the browser. Please open the URL manually.")
	}

	fmt.Println()
	fmt.Print("After authorizing, paste the code#state string here: ")
	input, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}
	input = strings.TrimSpace(input)

	parts := strings.SplitN(input, "#", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid format: expected code#state")
	}
	code, state := parts[0], parts[1]
	if state != params.State {
		return fmt.Errorf("state mismatch — please try again")
	}

	fmt.Println("Exchanging authorization code...")
	token, resp, err := anthropicOAuth.ExchangeCode(loginCtx, code, params.CodeVerifier, state)
	if err != nil {
		return fmt.Errorf("token exchange failed: %w", err)
	}

	if anthropicOAuth.HasInferenceScope(resp.Scope) {
		// Claude.ai Pro/Max subscriber: store bearer token.
		if err := c.SetConfigField(loginCtx, wsID, config.ScopeGlobal, "providers.anthropic.api_key", token.AccessToken); err != nil {
			return fmt.Errorf("failed to save credentials: %w", err)
		}
		fmt.Println()
		fmt.Println("Authenticated with Anthropic! Using bearer token for inference.")
		return nil
	}

	// Console user: create a permanent API key.
	fmt.Println("Creating API key via Anthropic Console...")
	apiKey, err := anthropicOAuth.CreateAPIKey(loginCtx, token.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to create API key: %w", err)
	}
	if err := c.SetConfigField(loginCtx, wsID, config.ScopeGlobal, "providers.anthropic.api_key", apiKey); err != nil {
		return fmt.Errorf("failed to save API key: %w", err)
	}
	fmt.Println()
	fmt.Println("Authenticated with Anthropic! API key saved.")
	return nil
}

func loginHyper(c *client.Client, wsID string) error {
	ctx := getLoginContext()

	resp, err := hyper.InitiateDeviceAuth(ctx)
	if err != nil {
		return err
	}

	if clipboard.WriteAll(resp.UserCode) == nil {
		fmt.Println("The following code should be on clipboard already:")
	} else {
		fmt.Println("Copy the following code:")
	}

	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Bold(true).Render(resp.UserCode))
	fmt.Println()
	fmt.Println("Press enter to open this URL, and then paste it there:")
	fmt.Println()
	fmt.Println(lipgloss.NewStyle().Hyperlink(resp.VerificationURL, "id=hyper").Render(resp.VerificationURL))
	fmt.Println()
	waitEnter()
	if err := browser.OpenURL(resp.VerificationURL); err != nil {
		fmt.Println("Could not open the URL. You'll need to manually open the URL in your browser.")
	}

	fmt.Println("Exchanging authorization code...")
	refreshToken, err := hyper.PollForToken(ctx, resp.DeviceCode, resp.ExpiresIn)
	if err != nil {
		return err
	}

	fmt.Println("Exchanging refresh token for access token...")
	token, err := hyper.ExchangeToken(ctx, refreshToken)
	if err != nil {
		return err
	}

	fmt.Println("Verifying access token...")
	introspect, err := hyper.IntrospectToken(ctx, token.AccessToken)
	if err != nil {
		return fmt.Errorf("token introspection failed: %w", err)
	}
	if !introspect.Active {
		return fmt.Errorf("access token is not active")
	}

	if err := cmp.Or(
		c.SetConfigField(ctx, wsID, config.ScopeGlobal, "providers.hyper.api_key", token.AccessToken),
		c.SetConfigField(ctx, wsID, config.ScopeGlobal, "providers.hyper.oauth", token),
	); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("You're now authenticated with Hyper!")
	return nil
}

func loginCopilot(ctx context.Context, c *client.Client, wsID string) error {
	loginCtx := getLoginContext()

	cfg, err := c.GetConfig(ctx, wsID)
	if err == nil && cfg != nil {
		if pc, ok := cfg.Providers.Get("copilot"); ok && pc.OAuthToken != nil {
			fmt.Println("You are already logged in to GitHub Copilot.")
			return nil
		}
	}

	diskToken, hasDiskToken := copilot.RefreshTokenFromDisk()
	var token *oauth.Token

	switch {
	case hasDiskToken:
		fmt.Println("Found existing GitHub Copilot token on disk. Using it to authenticate...")

		t, err := copilot.RefreshToken(loginCtx, diskToken)
		if err != nil {
			return fmt.Errorf("unable to refresh token from disk: %w", err)
		}
		token = t
	default:
		fmt.Println("Requesting device code from GitHub...")
		dc, err := copilot.RequestDeviceCode(loginCtx)
		if err != nil {
			return err
		}

		fmt.Println()
		fmt.Println("Open the following URL and follow the instructions to authenticate with GitHub Copilot:")
		fmt.Println()
		fmt.Println(lipgloss.NewStyle().Hyperlink(dc.VerificationURI, "id=copilot").Render(dc.VerificationURI))
		fmt.Println()
		fmt.Println("Code:", lipgloss.NewStyle().Bold(true).Render(dc.UserCode))
		fmt.Println()
		fmt.Println("Waiting for authorization...")

		t, err := copilot.PollForToken(loginCtx, dc)
		if err == copilot.ErrNotAvailable {
			fmt.Println()
			fmt.Println("GitHub Copilot is unavailable for this account. To signup, go to the following page:")
			fmt.Println()
			fmt.Println(lipgloss.NewStyle().Hyperlink(copilot.SignupURL, "id=copilot-signup").Render(copilot.SignupURL))
			fmt.Println()
			fmt.Println("You may be able to request free access if eligible. For more information, see:")
			fmt.Println()
			fmt.Println(lipgloss.NewStyle().Hyperlink(copilot.FreeURL, "id=copilot-free").Render(copilot.FreeURL))
		}
		if err != nil {
			return err
		}
		token = t
	}

	if err := cmp.Or(
		c.SetConfigField(loginCtx, wsID, config.ScopeGlobal, "providers.copilot.api_key", token.AccessToken),
		c.SetConfigField(loginCtx, wsID, config.ScopeGlobal, "providers.copilot.oauth", token),
	); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("You're now authenticated with GitHub Copilot!")
	return nil
}

func getLoginContext() context.Context {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	go func() {
		<-ctx.Done()
		cancel()
		os.Exit(1)
	}()
	return ctx
}

func waitEnter() {
	_, _ = fmt.Scanln()
}
