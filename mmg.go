package main

import (
    "crypto/rand"
    "crypto/tls"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "math/big"
    "mime"
    "net/smtp"
    "os"
    "os/exec"
    "path/filepath"
    "runtime"
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

    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/chacha20"
    "golang.org/x/crypto/sha3"
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
    SMTPHost         string `yaml:"smtp_host"`
    SMTPPort         string `yaml:"smtp_port"`
    Username         string `yaml:"username"`
    Password         string `yaml:"password"`
    SocksPort        string `yaml:"socks_port"`
    EsubKey          string `yaml:"esub_key"`
    HashcashBits     string `yaml:"hashcash_bits"`
    HashcashReceiver string `yaml:"hashcash_receiver"`
    Theme            string `yaml:"theme"`
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
    themeEntry       *widget.Entry
    encodeMIMESubjectEntry *widget.Entry
    esubKeyEntry        *widget.Entry
    hashcashBitsEntry   *widget.Entry
    hashcashReceiverEntry *widget.Entry
}

var fixedSalt = []byte("61546a8cbbe0957d")

const (
	argon2Time    = 1
	argon2Memory  = 64 * 1024 // 64 MB
	argon2Threads = 4
	argon2KeyLen  = 32
)

func deriveArgon2Key(password string, salt []byte) []byte {
	if len(salt) != 16 {
		panic("Fixed salt must be exactly 16 bytes long")
	}
	return argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
}

type esub struct {
	key      string
	subject  string
}

func (e *esub) deriveKey() []byte {
	salt := []byte("fixed-salt-1234")
	key := argon2.IDKey(
		[]byte(e.key),
		salt,
		3,      // iterations
		64*1024, // 64MB memory
		4,      // threads
		32,     // output key length (32 bytes for ChaCha20)
	)
	return key
}

func (e *esub) esubtest() bool {
	if len(e.subject) != 48 { // 48 hex chars = 24 bytes
		return false
	}

	esubBytes, err := hex.DecodeString(e.subject)
	if err != nil || len(esubBytes) != 24 {
		return false
	}

	nonce := esubBytes[:12]
	receivedCiphertext := esubBytes[12:]

	key := e.deriveKey()
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return false
	}

	textHash := sha3.Sum256([]byte("text"))
	expectedCiphertext := make([]byte, 12)
	cipher.XORKeyStream(expectedCiphertext, textHash[:12])

	return hex.EncodeToString(expectedCiphertext) == hex.EncodeToString(receivedCiphertext)
}

func (e *esub) esubgen() string {
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}

	key := e.deriveKey()
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		panic(err)
	}

	textHash := sha3.Sum256([]byte("text"))
	ciphertext := make([]byte, 12)
	cipher.XORKeyStream(ciphertext, textHash[:12])

	return hex.EncodeToString(append(nonce, ciphertext...))
}

type encodeMIMESubject struct {
    Subject string
}

func (e encodeMIMESubject) encodeMIMESubject() string {
	if e.Subject == "" {
		return ""
	}

	encoded := mime.BEncoding.Encode("UTF-8", e.Subject)

	parts := strings.Split(encoded, "?=")
	if len(parts) <= 1 {
		return encoded
	}

	var result string
	for i, part := range parts[:len(parts)-1] {
		if i > 0 {
			result += ""
		}
		result += part + "?=\n"
	}
	result += parts[len(parts)-1]

	return strings.TrimSuffix(result, "\n")
}

func (g *GUI) showEsubDialog() {
    keyEntry := widget.NewEntry()
    keyEntry.SetText(g.esubKeyEntry.Text)
    content := container.NewVBox(
        widget.NewLabel("Enter your key:"),
        keyEntry,
        container.New(layout.NewHBoxLayout(),
            layout.NewSpacer(),
            widget.NewButton("Generate", func() {
                if keyEntry.Text == "" {
                    dialog.ShowError(fmt.Errorf("Key cannot be empty"), g.window)
                    return
                }
                e := esub{key: keyEntry.Text}
                esubStr := e.esubgen()
                err := clipboard.WriteAll(esubStr)
                if err != nil {
                    dialog.ShowError(fmt.Errorf("Failed to copy to clipboard: %v", err), g.window)
                    return
                }
                // dialog.ShowInformation("Success", "esub copied to clipboard.", g.window)
            }),
            layout.NewSpacer(),
        ),
    )
    dialog.ShowCustom("esub Generator", "Close", content, g.window)
}

func (g *GUI) showHashcashDialog() {
    bitsEntry := widget.NewEntry()
    bitsEntry.SetText(g.hashcashBitsEntry.Text)
    receiverEntry := widget.NewEntry()
    receiverEntry.SetText(g.hashcashReceiverEntry.Text)
    content := container.NewVBox(
        widget.NewLabel("Bits:"),
        bitsEntry,
        widget.NewLabel("Receiver:"),
        receiverEntry,
        container.New(layout.NewHBoxLayout(),
            layout.NewSpacer(),
            widget.NewButton("Generate", func() {
                _, err := exec.LookPath("hashcash")
                if err != nil {
                    dialog.ShowError(fmt.Errorf("hashcash is not installed"), g.window)
                    return
                }
                if runtime.GOOS == "linux" {
                    if _, err := exec.LookPath("xclip"); err != nil {
                        dialog.ShowError(fmt.Errorf("xclip is not installed"), g.window)
                        return
                    }
                }
                cmd := exec.Command("hashcash", "-mb"+bitsEntry.Text, "-z", "12", "-r", receiverEntry.Text)
                out, err := cmd.Output()
                if err != nil {
                    dialog.ShowError(fmt.Errorf("Failed to generate hashcash: %v", err), g.window)
                    return
                }
                err = clipboard.WriteAll(string(out))
                if err != nil {
                    dialog.ShowError(fmt.Errorf("Failed to copy to clipboard: %v", err), g.window)
                    return
                }
                // dialog.ShowInformation("Success.", "Hashcash copied to clipboard.", g.window)
            }),
            layout.NewSpacer(),
        ),
    )
    dialog.ShowCustom("Hashcash Generator", "Close", content, g.window)
}

func (g *GUI) showencodeMIMESubjectDialog() {
    content := container.NewVBox(
        widget.NewLabel("Enter your Subject:"),
        g.encodeMIMESubjectEntry,
        container.New(layout.NewHBoxLayout(),
            layout.NewSpacer(),
            widget.NewButton("Convert", func() {
                if g.encodeMIMESubjectEntry.Text == "" {
                    dialog.ShowError(fmt.Errorf("Subject cannot be empty"), g.window)
                    return
                }
                s := encodeMIMESubject{Subject: g.encodeMIMESubjectEntry.Text}
                encodeMIMESubjectStr := s.encodeMIMESubject()
                err := clipboard.WriteAll(encodeMIMESubjectStr)
                if err != nil {
                    dialog.ShowError(fmt.Errorf("Failed to copy to clipboard: %v", err), g.window)
                    return
                }
                // dialog.ShowInformation("Success.", "MIME encoded Subject: copied to clipboard.", g.window)
            }),
            layout.NewSpacer(),
        ),
    )
    dialog.ShowCustom("MIME Subject: Encoder", "Close", content, g.window)
}

func (g *GUI) createMiscMenu() *fyne.Menu {
    esubItem := fyne.NewMenuItem("esub", func() {
        g.showEsubDialog()
    })
    hashcashItem := fyne.NewMenuItem("hashcash", func() {
        g.showHashcashDialog()
    })
    SubjectItem := fyne.NewMenuItem("MIME", func() {
        g.showencodeMIMESubjectDialog()
    })
    return fyne.NewMenu("Tools", esubItem, hashcashItem, SubjectItem)
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
    g.esubKeyEntry.SetText(config.EsubKey)
    g.hashcashBitsEntry.SetText(config.HashcashBits)
    g.hashcashReceiverEntry.SetText(config.HashcashReceiver)
    g.themeEntry.SetText(config.Theme)
    
    if config.Theme == "light" {
        g.app.Settings().SetTheme(theme.LightTheme())
    } else {
        g.app.Settings().SetTheme(theme.DarkTheme())
    }
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
    
    themeValue := strings.ToLower(strings.TrimSpace(g.themeEntry.Text))
    if themeValue != "light" && themeValue != "dark" {
        dialog.ShowError(fmt.Errorf("Theme must be either 'light' or 'dark'"), g.window)
        return
    }
    
    config := Config{
        SMTPHost:         g.hostEnt.Text,
        SMTPPort:         g.portEnt.Text,
        Username:         g.usernameEnt.Text,
        Password:         g.passwordEnt.Text,
        SocksPort:        g.socksPortEnt.Text,
        EsubKey:          g.esubKeyEntry.Text,
        HashcashBits:     g.hashcashBitsEntry.Text,
        HashcashReceiver: g.hashcashReceiverEntry.Text,
        Theme:            themeValue,
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
    
    if themeValue == "light" {
        g.app.Settings().SetTheme(theme.LightTheme())
    } else {
        g.app.Settings().SetTheme(theme.DarkTheme())
    }
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
                Description: "Default email template",
            },
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
        selected := g.templates[g.selectedTemplate]
        full := selected.Headers + "\n" + selected.Body
        if err := clipboard.WriteAll(full); err != nil {
            dialog.ShowError(fmt.Errorf("Failed to copy to clipboard: %v", err), g.window)
        }
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

    clearButton := widget.NewButton("Clear Canvas", func() {
        g.messageEnt.SetText("")
    })

    clearClipboardButton := widget.NewButton("Clear Clipboard", func() {
        err := clipboard.WriteAll("")
        if err != nil {
            dialog.ShowError(fmt.Errorf("Failed to clear clipboard: %v", err), g.window)
            return
        }
    })

    sendButton := widget.NewButton("Send Email", g.sendEmail)

    buttonContainer := container.NewHBox(
        layout.NewSpacer(),
        pasteButton,
        clearButton,
        clearClipboardButton,
        sendButton,
        layout.NewSpacer(),
    )

    return container.NewBorder(
        nil,
        container.NewVBox(buttonContainer, g.statusLabel),
        nil, nil,
        container.NewScroll(g.messageEnt),
    )
}

func (g *GUI) buildConfigTab() *fyne.Container {
    g.themeEntry = widget.NewEntry()
    g.themeEntry.SetPlaceHolder("Enter 'light' or 'dark'")
    g.themeEntry.SetText("dark")

    loadButton := widget.NewButton("Load Config", g.loadConfig)
    saveButton := widget.NewButton("Save Config", func() {
        themeValue := strings.ToLower(strings.TrimSpace(g.themeEntry.Text))
        if themeValue != "light" && themeValue != "dark" {
            dialog.ShowError(fmt.Errorf("Theme must be either 'light' or 'dark'"), g.window)
            return
        }
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
            widget.NewFormItem("esub Key", g.esubKeyEntry),
            widget.NewFormItem("Hashcash Bits", g.hashcashBitsEntry),
            widget.NewFormItem("Hashcash Receiver", g.hashcashReceiverEntry),
            widget.NewFormItem("Theme (light/dark)", g.themeEntry),
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
    mainContainer := container.NewBorder(nil, nil, nil, nil, tabs)
    g.window.SetContent(mainContainer)
}

func NewGUI() *GUI {
    myApp := app.New()
    myApp.Settings().SetTheme(theme.DarkTheme())
    window := myApp.NewWindow("Mini Mailer")
    window.Resize(fyne.NewSize(800, 600))
    window.SetOnClosed(func() {
        window.Clipboard().SetContent("")
    })

    gui := &GUI{
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
        encodeMIMESubjectEntry: widget.NewEntry(),
        esubKeyEntry:   widget.NewEntry(),
        hashcashBitsEntry:   widget.NewEntry(),
        hashcashReceiverEntry: widget.NewEntry(),
        themeEntry:      widget.NewEntry(),
    }
    return gui
}

func (g *GUI) ShowAndRun() {
    g.hostEnt = widget.NewEntry()
    g.portEnt = widget.NewEntry()
    g.usernameEnt = widget.NewEntry()
    g.passwordEnt = widget.NewEntry()
    g.socksPortEnt = widget.NewEntry()
    g.esubKeyEntry = widget.NewEntry()
    g.hashcashBitsEntry = widget.NewEntry()
    g.hashcashReceiverEntry = widget.NewEntry()
    g.configFile = widget.NewEntry()
    g.encodeMIMESubjectEntry = widget.NewEntry()

    miscMenu := g.createMiscMenu()
    mainMenu := fyne.NewMainMenu(miscMenu)
    g.window.SetMainMenu(mainMenu)

    g.loadConfig()
    g.buildUI()
    g.window.ShowAndRun()
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
            headers[strings.TrimSpace(strings.ToLower(pair[0]))] = strings.TrimSpace(pair[1])
        }
    }
    return headers
}

func extractEmailFromHeaders(headers map[string]string, headerKey string) string {
    if value, exists := headers[strings.ToLower(headerKey)]; exists {
        if strings.Contains(value, "<") && strings.Contains(value, ">") {
            start := strings.LastIndex(value, "<")
            end := strings.LastIndex(value, ">")
            return value[start : end+1]
        }
        return value
    }
    return ""
}

func isValidEmail(email string) bool {
    return strings.Contains(email, "@") && strings.Contains(email, ".")
}

func (g *GUI) sendEmail() {
    rawContent := normalizeLineEndings(g.messageEnt.Text)
    headers := parseHeaders(rawContent)
    from := extractEmailFromHeaders(headers, "from")
    to := extractEmailFromHeaders(headers, "to")
    if !isValidEmail(from) || !isValidEmail(to) {
        fyne.Do(func() {
            dialog.ShowError(fmt.Errorf("Invalid 'From' or 'To' address"), g.window)
        })
        return
    }

    var messageIDHeader, dateHeader string
    if _, exists := headers["message-id"]; !exists {
        messageIDHeader = fmt.Sprintf("Message-ID: %s\r\n", generateMessageID())
    }
    if _, exists := headers["date"]; !exists {
        dateHeader = fmt.Sprintf("Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
    }

    parts := strings.SplitN(rawContent, "\r\n\r\n", 2)
    if len(parts) == 2 {
        rawContent = parts[0] + "\r\n" + messageIDHeader + dateHeader + "\r\n\r\n" + parts[1]
    } else {
        rawContent = rawContent + "\r\n" + messageIDHeader + dateHeader + "\r\n"
    }

    fyne.Do(func() {
        g.statusLabel.SetText("Starting SMTP session...")
    })

    go func() {
        updateStatus := func(text string) {
            fyne.Do(func() {
                g.statusLabel.SetText(text)
            })
        }

        showError := func(err error) {
            fyne.Do(func() {
                dialog.ShowError(err, g.window)
            })
        }

        updateStatus("Connecting to SOCKS proxy...")
        dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:"+g.socksPortEnt.Text, nil, proxy.Direct)
        if err != nil {
            updateStatus("SOCKS Error: " + err.Error())
            showError(fmt.Errorf("SOCKS5 error: %v", err))
            return
        }

        updateStatus("Connecting to SMTP server...")
        conn, err := dialer.Dial("tcp", g.hostEnt.Text+":"+g.portEnt.Text)
        if err != nil {
            updateStatus("Connection Error: " + err.Error())
            showError(fmt.Errorf("Connection failed: %v", err))
            return
        }
        defer conn.Close()

        updateStatus("Starting SMTP handshake...")
        client, err := smtp.NewClient(conn, g.hostEnt.Text)
        if err != nil {
            updateStatus("SMTP Init Error: " + err.Error())
            showError(fmt.Errorf("SMTP init failed: %v", err))
            return
        }
        defer client.Quit()

        updateStatus("Starting TLS...")
        if err := client.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
            updateStatus("TLS Error: " + err.Error())
            showError(fmt.Errorf("TLS failed: %v", err))
            return
        }

        if g.usernameEnt.Text != "" && g.passwordEnt.Text != "" {
            updateStatus("Authenticating...")
            auth := smtp.PlainAuth("", g.usernameEnt.Text, g.passwordEnt.Text, g.hostEnt.Text)
            if err := client.Auth(auth); err != nil {
                updateStatus("Auth Error: " + err.Error())
                showError(fmt.Errorf("Auth failed: %v", err))
                return
            }
        }

        updateStatus("Sending MAIL FROM...")
        if err := client.Mail(from); err != nil {
            updateStatus("MAIL FROM Error: " + err.Error())
            showError(fmt.Errorf("MAIL FROM failed: %v", err))
            return
        }

        updateStatus("Sending RCPT TO...")
        if err := client.Rcpt(to); err != nil {
            updateStatus("RCPT TO Error: " + err.Error())
            showError(fmt.Errorf("RCPT TO failed: %v", err))
            return
        }

        updateStatus("Sending DATA...")
        w, err := client.Data()
        if err != nil {
            updateStatus("DATA Error: " + err.Error())
            showError(fmt.Errorf("DATA failed: %v", err))
            return
        }
        defer w.Close()

        if _, err := w.Write([]byte(rawContent)); err != nil {
            updateStatus("Write Error: " + err.Error())
            showError(fmt.Errorf("Message write failed: %v", err))
            return
        }

        updateStatus("Email sent successfully")
    }()
}

func main() {
    gui := NewGUI()
    gui.ShowAndRun()
}