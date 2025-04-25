package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math/big"
	"net/smtp"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v2"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
        "fyne.io/fyne/v2/layout"
        "fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"golang.org/x/net/proxy"

	"github.com/atotto/clipboard"
)

const (
	defaultConfigFile = "config.yaml"
	templateFile      = "templates.json"
	configDir         = "minimailer"
	configExtension   = ".yaml"
)

type Config struct {
	SMTPHost  string `yaml:"smtp_host"`
	SMTPPort  string `yaml:"smtp_port"`
	Username  string `yaml:"username"`
	Password  string `yaml:"password"`
	SocksPort string `yaml:"socks_port"`
}

type Template struct {
	Name        string `json:"name"`
	Headers     string `json:"headers"`
	Body        string `json:"body"`
	Description string `json:"description"`
}

type GUI struct {
	app              fyne.App
	window           fyne.Window
	templates        []Template
	templateList     *widget.List
	selectedTemplate int
	templateName     *widget.Entry
	templateDesc     *widget.Entry
	templateEditor   *widget.Entry
	usernameEnt      *widget.Entry
	passwordEnt      *widget.Entry
	socksPortEnt     *widget.Entry
	hostEnt          *widget.Entry
	portEnt          *widget.Entry
	messageEnt       *widget.Entry
	statusLabel      *widget.Label
	copiedHeaders    string
	copiedBody       string
	configFile       *widget.Entry
	smtpLogLabel     *widget.Label
}

func (g *GUI) loadConfig() {
	configPath, err := os.UserConfigDir()
	if err != nil {
		dialog.ShowError(fmt.Errorf("Failed to get config directory: %v", err), g.window)
		return
	}
	appDir := filepath.Join(configPath, configDir)

	configFilePath := filepath.Join(appDir, "config.yaml")
	if g.configFile.Text != "" {
		configFilePath = filepath.Join(appDir, g.configFile.Text+configExtension)
	}

	if _, err := os.Stat(configFilePath); os.IsNotExist(err) {
		dialog.ShowError(fmt.Errorf("Config file does not exist: %s", configFilePath), g.window)
		return
	}

	data, err := os.ReadFile(configFilePath)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Failed to read config: %v", err), g.window)
		return
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		dialog.ShowError(fmt.Errorf("Failed to parse config: %v", err), g.window)
		return
	}

	g.hostEnt.SetText(config.SMTPHost)
	g.portEnt.SetText(config.SMTPPort)
	g.usernameEnt.SetText(config.Username)
	g.passwordEnt.SetText(config.Password)
	g.socksPortEnt.SetText(config.SocksPort)

	//dialog.ShowInformation("Success", "Configuration loaded successfully!", g.window)
}

func (g *GUI) saveConfig() {
	configPath, err := os.UserConfigDir()
	if err != nil {
		dialog.ShowError(fmt.Errorf("Failed to get config directory: %v", err), g.window)
		return
	}
	appDir := filepath.Join(configPath, configDir)
	if err := os.MkdirAll(appDir, 0755); err != nil {
		dialog.ShowError(fmt.Errorf("Failed to create config directory: %v", err), g.window)
		return
	}

	configFilePath := filepath.Join(appDir, "config.yaml")
	if g.configFile.Text != "" {
		configFilePath = filepath.Join(appDir, g.configFile.Text+configExtension)
	}

	config := Config{
		SMTPHost:  g.hostEnt.Text,
		SMTPPort:  g.portEnt.Text,
		Username:  g.usernameEnt.Text,
		Password:  g.passwordEnt.Text,
		SocksPort: g.socksPortEnt.Text,
	}

	data, err := yaml.Marshal(&config)
	if err != nil {
		dialog.ShowError(fmt.Errorf("Failed to serialize config: %v", err), g.window)
		return
	}

	if err := os.WriteFile(configFilePath, data, 0644); err != nil {
		dialog.ShowError(fmt.Errorf("Failed to save config: %v", err), g.window)
		return
	}

	//dialog.ShowInformation("Success", "Config saved successfully!", g.window)
}

func (g *GUI) loadTemplates() error {
	configPath, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	appDir := filepath.Join(configPath, configDir)
	if err := os.MkdirAll(appDir, 0755); err != nil {
		return err
	}
	templatePath := filepath.Join(appDir, templateFile)
	if _, err := os.Stat(templatePath); os.IsNotExist(err) {
		g.templates = []Template{
			{
				Name:        "Standard",
				Description: "Default email template",			},
		}
		return g.saveTemplates()
	}
	data, err := os.ReadFile(templatePath)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &g.templates)
}

func (g *GUI) saveTemplates() error {
	configPath, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	templatePath := filepath.Join(configPath, configDir, templateFile)
	data, err := json.MarshalIndent(g.templates, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(templatePath, data, 0644)
}

func (g *GUI) saveTemplate() {
	if g.templateName.Text == "" {
		dialog.ShowError(fmt.Errorf("Template name is required"), g.window)
		return
	}

	headers := strings.TrimSpace(g.templateEditor.Text)
	body := strings.TrimSpace(g.messageEnt.Text)

	newTemplate := Template{
		Name:        g.templateName.Text,
		Description: g.templateDesc.Text,
		Headers:     headers,
		Body:        body,
	}

	found := false
	for i, t := range g.templates {
		if t.Name == newTemplate.Name {
			g.templates[i] = newTemplate
			found = true
			break
		}
	}
	if !found {
		g.templates = append(g.templates, newTemplate)
	}
	if err := g.saveTemplates(); err != nil {
		dialog.ShowError(err, g.window)
		return
	}
	g.templateList.Refresh()
	//dialog.ShowInformation("Success", "Template saved successfully", g.window)
}

func (g *GUI) selectTemplate(id widget.ListItemID) {
	g.selectedTemplate = id
	template := g.templates[id]
	g.templateName.SetText(template.Name)
	g.templateDesc.SetText(template.Description)
	g.templateEditor.SetText(template.Headers)
	g.messageEnt.SetText(template.Body)
}

func (g *GUI) deleteTemplate() {
	if g.selectedTemplate < 0 || g.selectedTemplate >= len(g.templates) {
		dialog.ShowError(fmt.Errorf("No template selected"), g.window)
		return
	}

	g.templates = append(g.templates[:g.selectedTemplate], g.templates[g.selectedTemplate+1:]...)

	if err := g.saveTemplates(); err != nil {
		dialog.ShowError(err, g.window)
		return
	}

	g.templateList.Refresh()
	g.templateName.SetText("")
	g.templateDesc.SetText("")
	g.templateEditor.SetText("")
	g.messageEnt.SetText("")
	g.selectedTemplate = -1
}

func (g *GUI) buildTemplateEditor() *fyne.Container {
	g.templateList = widget.NewList(
		func() int { return len(g.templates) },
		func() fyne.CanvasObject { return widget.NewLabel("Template") },
		func(id widget.ListItemID, o fyne.CanvasObject) {
			o.(*widget.Label).SetText(g.templates[id].Name)
		},
	)
	g.templateList.OnSelected = g.selectTemplate
	g.templateName = widget.NewEntry()
	g.templateName.SetPlaceHolder("Template name")
	g.templateDesc = widget.NewEntry()
	g.templateDesc.SetPlaceHolder("Description")
	g.templateEditor = widget.NewMultiLineEntry()
	g.templateEditor.SetPlaceHolder("Email headers")

	copyButton := widget.NewButton("Copy", func() {
		if g.selectedTemplate < 0 || g.selectedTemplate >= len(g.templates) {
			dialog.ShowError(fmt.Errorf("No template selected"), g.window)
			return
		}
		selectedTemplate := g.templates[g.selectedTemplate]
		g.copiedHeaders = selectedTemplate.Headers
		g.copiedBody = selectedTemplate.Body
		fullContent := selectedTemplate.Headers + "\n\n" + selectedTemplate.Body
		if err := clipboard.WriteAll(fullContent); err != nil {
			dialog.ShowError(fmt.Errorf("Failed to copy to clipboard: %v", err), g.window)
			return
		}
		//dialog.ShowInformation("Copied", "Template content copied to clipboard!", g.window)
	})

	controls := container.NewHBox(
		widget.NewButton("New", func() {
			g.templateName.SetText("")
			g.templateDesc.SetText("")
			g.templateEditor.SetText("")
			g.messageEnt.SetText("")
			g.selectedTemplate = -1
		}),
		widget.NewButton("Save", g.saveTemplate),
		widget.NewButton("Delete", g.deleteTemplate),
		copyButton,
	)

	return container.NewBorder(
		container.NewVBox(
			widget.NewLabel("Templates"),
			g.templateList,
			widget.NewSeparator(),
			widget.NewForm(
				widget.NewFormItem("Name", g.templateName),
				widget.NewFormItem("Description", g.templateDesc),
			),
			controls,
		),
		nil, nil, nil,
		container.NewScroll(g.templateEditor),
	)
}

func (g *GUI) buildComposeTab() *fyne.Container {
    g.messageEnt = widget.NewMultiLineEntry()
    g.messageEnt.TextStyle = fyne.TextStyle{Monospace: true}
    g.statusLabel = widget.NewLabel("Ready to send")

    // Button: Paste Template
    pasteButton := widget.NewButton("Paste Template", func() {
        content, err := clipboard.ReadAll()
        if err != nil {
            dialog.ShowError(fmt.Errorf("Failed to read clipboard: %v", err), g.window)
            return
        }
        if content == "" {
            dialog.ShowError(fmt.Errorf("Clipboard is empty"), g.window)
            return
        }
        g.messageEnt.SetText(content)
    })

    // Button: Clear Canvas
    clearButton := widget.NewButton("Clear Canvas", func() {
        g.messageEnt.SetText("")
    })

    // Button: Clear Clipboard
    clearClipboardButton := widget.NewButton("Clear Clipboard", func() {
        err := clipboard.WriteAll("")
        if err != nil {
            dialog.ShowError(fmt.Errorf("Failed to clear clipboard: %v", err), g.window)
            return
        }
    })

    // Button: Send Email
    sendButton := widget.NewButton("Send Email", g.sendEmail)

    buttonContainer := container.NewHBox(
        layout.NewSpacer(),
        pasteButton,
        clearButton,
        clearClipboardButton, // Fügen Sie den neuen Button hier ein
        sendButton,
        layout.NewSpacer(),
    )

    return container.NewBorder(
        nil,
        container.NewVBox(
            buttonContainer,
            g.statusLabel,
        ),
        nil, nil,
        container.NewScroll(g.messageEnt),
    )
}
func (g *GUI) buildConfigTab() *fyne.Container {
    loadButton := widget.NewButton("Load Config", func() {
        g.loadConfig()
    })
    saveButton := widget.NewButton("Save Config", func() {
        g.saveConfig()
    })
    return container.NewVBox(
        widget.NewForm(
            widget.NewFormItem("SMTP Host", g.hostEnt),
            widget.NewFormItem("SMTP Port", g.portEnt),
            widget.NewFormItem("Username", g.usernameEnt),
            widget.NewFormItem("Password", g.passwordEnt),
            widget.NewFormItem("SOCKS5 Port", g.socksPortEnt),
            widget.NewFormItem("Config File", g.configFile),
        ),
        container.NewHBox(loadButton, saveButton),
    )
}

func (g *GUI) buildUI() {
	if err := g.loadTemplates(); err != nil {
		dialog.ShowError(err, g.window)
	}
	tabs := container.NewAppTabs(
		container.NewTabItem("Compose", g.buildComposeTab()),
		container.NewTabItem("Templates", g.buildTemplateEditor()),
		container.NewTabItem("Configuration", g.buildConfigTab()),
	)

	mainContainer := container.NewBorder(
		nil, nil, nil, nil,
		tabs,
	)
	g.window.SetContent(mainContainer)
	g.window.SetCloseIntercept(func() {
		g.app.Quit()
	})
}

func (g *GUI) log(message string) {
	const maxLogLength = 80
	if len(message) > maxLogLength {
		message = message[:maxLogLength] + "..."
	}

	g.statusLabel.SetText(message)

	if strings.Contains(message, "Email sent successfully") {
		time.AfterFunc(5*time.Second, func() {
			g.statusLabel.SetText("Ready to send")
		})
	}
}

func NewGUI() *GUI {
	myApp := app.New()
        myApp.Settings().SetTheme(theme.LightTheme())
	window := myApp.NewWindow("Mini Mailer")
	window.Resize(fyne.NewSize(800, 600))
	return &GUI{
		app:             myApp,
		window:          window,
		templates:       []Template{},
		selectedTemplate: -1,
		configFile:      widget.NewEntry(),
		messageEnt:      widget.NewMultiLineEntry(),
		hostEnt:         widget.NewEntry(),
		portEnt:         widget.NewEntry(),
		usernameEnt:     widget.NewEntry(),
		passwordEnt:     widget.NewEntry(),
		socksPortEnt:    widget.NewEntry(),
		templateName:    widget.NewEntry(),
		templateDesc:    widget.NewEntry(),
		templateEditor:  widget.NewMultiLineEntry(),
		statusLabel:     widget.NewLabel("Ready to send"),
	}
}

func (g *GUI) ShowAndRun() {
	if err := g.loadTemplates(); err != nil {
		dialog.ShowError(err, g.window)
	}

	g.hostEnt = widget.NewEntry()
	g.portEnt = widget.NewEntry()
	g.usernameEnt = widget.NewEntry()
	g.passwordEnt = widget.NewEntry()
	g.socksPortEnt = widget.NewEntry()

	g.loadConfig()
	g.buildUI()
	g.window.ShowAndRun()
}

func main() {
	gui := NewGUI()
	gui.ShowAndRun()
}

func normalizeLineEndings(input string) string {
	return strings.ReplaceAll(input, "\n", "\r\n")
}

func generateMessageID() string {
	alphanumeric := "abcdefghijklmnopqrstuvwxyz0123456789"
	randomPart1 := make([]byte, 10)
	for i := range randomPart1 {
		randomIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphanumeric))))
		randomPart1[i] = alphanumeric[randomIndex.Int64()]
	}

	unixTime := time.Now().Unix()

	randomHostname := make([]byte, 5)
	for i := range randomHostname {
		randomIndex, _ := rand.Int(rand.Reader, big.NewInt(26))
		randomHostname[i] = 'a' + byte(randomIndex.Int64())
	}

	randomTLD := make([]byte, 2)
	for i := range randomTLD {
		randomIndex, _ := rand.Int(rand.Reader, big.NewInt(26))
		randomTLD[i] = 'a' + byte(randomIndex.Int64())
	}

	return fmt.Sprintf("<%s.%d@%s.%s>", randomPart1, unixTime, randomHostname, randomTLD)
}

func parseHeaders(rawContent string) map[string]string {
	headers := make(map[string]string)
	parts := strings.SplitN(rawContent, "\r\n\r\n", 2)
	headerPart := parts[0]

	lines := strings.Split(headerPart, "\r\n")
	for _, line := range lines {
		if line == "" {
			break
		}
		pair := strings.SplitN(line, ": ", 2)
		if len(pair) == 2 {
			key := strings.TrimSpace(strings.ToLower(pair[0]))
			value := strings.TrimSpace(pair[1])
			headers[key] = value
		}
	}
	return headers
}

func extractEmailFromHeaders(headers map[string]string, headerKey string) string {
    if value, exists := headers[strings.ToLower(headerKey)]; exists {
        if strings.Contains(value, "<") && strings.Contains(value, ">") {
            startBracket := strings.LastIndex(value, "<")
            endBracket := strings.LastIndex(value, ">")
            return value[startBracket : endBracket+1]
        }
        return value
    }
    return ""
}

func isValidEmail(email string) bool {
        return strings.Contains(email, "@") && strings.Contains(email, ".")
}

func (g *GUI) sendEmail() {
    // Normalize line endings to ensure consistent processing
    rawContent := normalizeLineEndings(g.messageEnt.Text)
    headers := parseHeaders(rawContent)
    from := extractEmailFromHeaders(headers, "from")
    to := extractEmailFromHeaders(headers, "to")

    // Validate email addresses
    if !isValidEmail(from) || !isValidEmail(to) {
        dialog.ShowError(fmt.Errorf("Invalid 'From' or 'To' address"), g.window)
        return
    }

    // Generate missing headers
    var messageIDHeader, dateHeader string
    if _, exists := headers["message-id"]; !exists {
        messageIDHeader = fmt.Sprintf("Message-ID: %s\r\n", generateMessageID())
    }
    if _, exists := headers["date"]; !exists {
        dateHeader = fmt.Sprintf("Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
    }

    // Split into headers and body
    parts := strings.SplitN(rawContent, "\r\n\r\n", 2)
    var fullMessage string
    if len(parts) == 2 {
        // Combine existing headers with new headers
        fullMessage = parts[0] + "\r\n" + messageIDHeader + dateHeader + "\r\n\r\n" + parts[1]
    } else {
        // No body found, just add headers
        fullMessage = rawContent + "\r\n" + messageIDHeader + dateHeader + "\r\n"
    }

    parts = strings.SplitN(rawContent, "\r\n\r\n", 2)
    if len(parts) == 2 {
        headers := strings.Split(parts[0], "\r\n")
        var newHeaders []string
        for _, header := range headers {
            newHeaders = append(newHeaders, header)
            if strings.HasPrefix(strings.ToLower(header), "subject:") {
                if messageIDHeader != "" {
                    newHeaders = append(newHeaders, strings.TrimRight(messageIDHeader, "\r\n"))
                }
                if dateHeader != "" {
                    newHeaders = append(newHeaders, strings.TrimRight(dateHeader, "\r\n"))
                }
            }
        }
        fullMessage = strings.Join(newHeaders, "\r\n") + "\r\n\r\n" + parts[1]
    } else {
        fullMessage = rawContent + "\r\n" + messageIDHeader + dateHeader + "\r\n"
    }

    g.statusLabel.SetText("Starting SMTP session...")

    go func() {
        fyne.DoAndWait(func() {
            g.statusLabel.SetText("Connecting to SOCKS proxy...")
        })

        dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:"+g.socksPortEnt.Text, nil, proxy.Direct)
        if err != nil {
            fyne.DoAndWait(func() {
                g.statusLabel.SetText("SOCKS Error: " + err.Error())
                dialog.ShowError(fmt.Errorf("SOCKS5 error: %v", err), g.window)
            })
            return
        }

        fyne.DoAndWait(func() {
            g.statusLabel.SetText("Connecting to SMTP server...")
        })

        conn, err := dialer.Dial("tcp", g.hostEnt.Text+":"+g.portEnt.Text)
        if err != nil {
            fyne.DoAndWait(func() {
                g.statusLabel.SetText("Connection Error: " + err.Error())
                dialog.ShowError(fmt.Errorf("Connection failed: %v", err), g.window)
            })
            return
        }
        defer conn.Close()

        fyne.DoAndWait(func() {
            g.statusLabel.SetText("Starting SMTP handshake...")
        })

        client, err := smtp.NewClient(conn, g.hostEnt.Text)
        if err != nil {
            fyne.DoAndWait(func() {
                g.statusLabel.SetText("SMTP Init Error: " + err.Error())
                dialog.ShowError(fmt.Errorf("SMTP init failed: %v", err), g.window)
            })
            return
        }
        defer client.Quit()

        fyne.DoAndWait(func() {
            g.statusLabel.SetText("Starting TLS...")
        })

        if err = client.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
            fyne.DoAndWait(func() {
                g.statusLabel.SetText("TLS Error: " + err.Error())
                dialog.ShowError(fmt.Errorf("TLS failed: %v", err), g.window)
            })
            return
        }

        if g.usernameEnt.Text != "" && g.passwordEnt.Text != "" {
            fyne.DoAndWait(func() {
                g.statusLabel.SetText("Authenticating...")
            })
            auth := smtp.PlainAuth("", g.usernameEnt.Text, g.passwordEnt.Text, g.hostEnt.Text)
            if err = client.Auth(auth); err != nil {
                fyne.DoAndWait(func() {
                    g.statusLabel.SetText("Auth Error: " + err.Error())
                    dialog.ShowError(fmt.Errorf("Auth failed: %v", err), g.window)
                })
                return
            }
        }

        fyne.DoAndWait(func() {
            g.statusLabel.SetText("Sending MAIL FROM...")
        })

        if err = client.Mail(from); err != nil {
            fyne.DoAndWait(func() {
                g.statusLabel.SetText("MAIL FROM Error: " + err.Error())
                dialog.ShowError(fmt.Errorf("MAIL FROM failed: %v", err), g.window)
            })
            return
        }

        fyne.DoAndWait(func() {
            g.statusLabel.SetText("Sending RCPT TO...")
        })

        if err = client.Rcpt(to); err != nil {
            fyne.DoAndWait(func() {
                g.statusLabel.SetText("RCPT TO Error: " + err.Error())
                dialog.ShowError(fmt.Errorf("RCPT TO failed: %v", err), g.window)
            })
            return
        }

        fyne.DoAndWait(func() {
            g.statusLabel.SetText("Sending DATA...")
        })

        w, err := client.Data()
        if err != nil {
            fyne.DoAndWait(func() {
                g.statusLabel.SetText("DATA Error: " + err.Error())
                dialog.ShowError(fmt.Errorf("DATA failed: %v", err), g.window)
            })
            return
        }
        defer w.Close()

        if _, err = w.Write([]byte(fullMessage)); err != nil {
            fyne.DoAndWait(func() {
                g.statusLabel.SetText("Write Error: " + err.Error())
                dialog.ShowError(fmt.Errorf("Message write failed: %v", err), g.window)
            })
            return
        }

        fyne.DoAndWait(func() {
            g.statusLabel.SetText("Email sent successfully")
            //dialog.ShowInformation("Success", "Email sent successfully!", g.window)
        })
    }()
}

