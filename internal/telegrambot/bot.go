// Package telegrambot implements a minimal long-polling Telegram bot that
// lets allowlisted admin user IDs add domains/IPs to a running smartdns
// instance through a guided, button-driven flow, without touching the
// server.
package telegrambot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"smartdns/internal/config"
)

const (
	apiBase        = "https://api.telegram.org/bot"
	pollTimeout    = 30 * time.Second
	flushTimeout   = 1 * time.Second
	httpClientSlop = 10 * time.Second
	retryBackoff   = 5 * time.Second
)

// convState tracks what a guided add-domain/add-ip conversation is waiting
// for next, per admin.
type convState int

const (
	stateNone convState = iota
	stateAwaitingDomain
	stateAwaitingIP
)

// Bot is a minimal long-polling Telegram bot scoped to two admin actions:
// appending a domain or an IP/CIDR to smartdns's list files and reloading
// the live config so the change takes effect immediately.
type Bot struct {
	token       string
	admins      map[int64]bool
	domainsFile string
	cidrsFile   string
	reload      func() error
	client      *http.Client

	mu     sync.Mutex
	states map[int64]convState
}

// New builds a Bot. reload is called after every successful add so the
// change takes effect without restarting smartdns.
func New(token string, adminIDs []int64, domainsFile, cidrsFile string, reload func() error) *Bot {
	admins := make(map[int64]bool, len(adminIDs))
	for _, id := range adminIDs {
		admins[id] = true
	}
	return &Bot{
		token:       token,
		admins:      admins,
		domainsFile: domainsFile,
		cidrsFile:   cidrsFile,
		reload:      reload,
		client:      &http.Client{Timeout: pollTimeout + httpClientSlop},
		states:      make(map[int64]convState),
	}
}

// Run polls Telegram for updates and handles admin commands until the
// process exits. Transient errors (network blips, a temporary Telegram
// outage) are logged and retried rather than propagated, so a flaky bot
// connection never brings down DNS/proxy serving.
func (b *Bot) Run() {
	offset := b.discardBacklog()
	for {
		updates, err := b.getUpdates(offset, pollTimeout)
		if err != nil {
			log.Printf("telegram bot: getUpdates: %v", err)
			time.Sleep(retryBackoff)
			continue
		}
		for _, u := range updates {
			offset = u.UpdateID + 1
			b.handle(u)
		}
	}
}

// discardBacklog skips any updates queued before the bot came online (e.g.
// a stale command sent while the process was down), so restarting smartdns
// never replays old admin actions.
func (b *Bot) discardBacklog() int64 {
	updates, err := b.getUpdates(0, flushTimeout)
	if err != nil || len(updates) == 0 {
		return 0
	}
	return updates[len(updates)-1].UpdateID + 1
}

type update struct {
	UpdateID      int64          `json:"update_id"`
	Message       *message       `json:"message"`
	CallbackQuery *callbackQuery `json:"callback_query"`
}

type message struct {
	Text string `json:"text"`
	From struct {
		ID int64 `json:"id"`
	} `json:"from"`
	Chat struct {
		ID   int64  `json:"id"`
		Type string `json:"type"`
	} `json:"chat"`
}

type callbackQuery struct {
	ID   string `json:"id"`
	From struct {
		ID int64 `json:"id"`
	} `json:"from"`
	Message *message `json:"message"`
	Data    string   `json:"data"`
}

func (b *Bot) getUpdates(offset int64, timeout time.Duration) ([]update, error) {
	v := url.Values{}
	v.Set("offset", fmt.Sprintf("%d", offset))
	v.Set("timeout", fmt.Sprintf("%d", int(timeout.Seconds())))

	resp, err := b.client.Get(b.api("getUpdates") + "?" + v.Encode())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var out struct {
		OK     bool     `json:"ok"`
		Result []update `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if !out.OK {
		return nil, fmt.Errorf("telegram API returned ok=false")
	}
	return out.Result, nil
}

func (b *Bot) handle(u update) {
	if u.CallbackQuery != nil {
		b.handleCallback(*u.CallbackQuery)
		return
	}
	if u.Message == nil || u.Message.Text == "" {
		return
	}

	// Only ever act in 1:1 chats: admin identity is keyed by user ID, which
	// only means "this specific admin" in a private chat.
	if u.Message.Chat.Type != "" && u.Message.Chat.Type != "private" {
		return
	}

	chatID := u.Message.Chat.ID
	fromID := u.Message.From.ID
	if !b.admins[fromID] {
		log.Printf("telegram bot: rejected command from unauthorized user id=%d", fromID)
		b.reply(chatID, "دسترسی نداری.")
		return
	}

	text := strings.TrimSpace(u.Message.Text)
	if !strings.HasPrefix(text, "/") {
		if b.consumeState(fromID, chatID, text) {
			return
		}
		b.sendMenu(chatID)
		return
	}

	fields := strings.Fields(text)
	cmd := fields[0]
	if i := strings.Index(cmd, "@"); i != -1 {
		cmd = cmd[:i] // strip the "@botname" suffix Telegram adds in group chats
	}
	var arg string
	if len(fields) > 1 {
		arg = fields[1]
	}

	switch cmd {
	case "/add_domain":
		if arg == "" {
			b.setState(fromID, stateAwaitingDomain)
			b.reply(chatID, "نام دامنه رو بفرست، مثلاً example.com")
			return
		}
		b.clearState(fromID)
		b.addDomain(chatID, arg)
	case "/add_ip":
		if arg == "" {
			b.setState(fromID, stateAwaitingIP)
			b.reply(chatID, "آی‌پی یا CIDR رو بفرست، مثلاً 203.0.113.5 یا 203.0.113.0/24")
			return
		}
		b.clearState(fromID)
		b.addIP(chatID, arg)
	case "/list":
		b.clearState(fromID)
		b.list(chatID)
	case "/cancel":
		b.clearState(fromID)
		b.reply(chatID, "لغو شد.")
	case "/start", "/help", "/menu":
		b.clearState(fromID)
		b.sendMenu(chatID)
	default:
		b.sendMenu(chatID)
	}
}

func (b *Bot) handleCallback(cq callbackQuery) {
	b.answerCallback(cq.ID)
	if cq.Message == nil {
		return
	}
	chatID := cq.Message.Chat.ID
	fromID := cq.From.ID
	if !b.admins[fromID] {
		log.Printf("telegram bot: rejected button press from unauthorized user id=%d", fromID)
		return
	}

	switch cq.Data {
	case "add_domain":
		b.setState(fromID, stateAwaitingDomain)
		b.reply(chatID, "نام دامنه رو بفرست، مثلاً example.com")
	case "add_ip":
		b.setState(fromID, stateAwaitingIP)
		b.reply(chatID, "آی‌پی یا CIDR رو بفرست، مثلاً 203.0.113.5 یا 203.0.113.0/24")
	case "list":
		b.clearState(fromID)
		b.list(chatID)
	}
}

// consumeState handles a plain-text reply to an in-progress guided flow. It
// reports whether text was consumed as part of that flow (vs. being an
// unrelated message with no flow in progress). On invalid input, the state
// is kept so the admin can just retry without pressing the button again.
func (b *Bot) consumeState(fromID, chatID int64, text string) bool {
	switch b.getState(fromID) {
	case stateAwaitingDomain:
		if b.addDomain(chatID, text) {
			b.clearState(fromID)
		}
		return true
	case stateAwaitingIP:
		if b.addIP(chatID, text) {
			b.clearState(fromID)
		}
		return true
	default:
		return false
	}
}

func (b *Bot) getState(id int64) convState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.states[id]
}

func (b *Bot) setState(id int64, s convState) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.states[id] = s
}

func (b *Bot) clearState(id int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.states, id)
}

// addDomain validates and appends domain, replies with the result, and
// reports whether the flow is done (true for success, already-present, or
// a reload failure; false only when the input itself was rejected, so the
// caller can prompt the admin to retry).
func (b *Bot) addDomain(chatID int64, domain string) bool {
	domain = strings.TrimSpace(domain)
	added, err := config.AppendDomain(b.domainsFile, domain)
	if err != nil {
		b.reply(chatID, fmt.Sprintf("❌ %v\nدوباره بفرست یا /cancel بزن.", err))
		return false
	}
	if !added {
		b.reply(chatID, fmt.Sprintf("این دامنه از قبل توی لیست هست: %s", domain))
		return true
	}
	if err := b.reload(); err != nil {
		b.reply(chatID, fmt.Sprintf("دامنه اضافه شد ولی اعمال (reload) شکست خورد: %v", err))
		return true
	}
	b.reply(chatID, fmt.Sprintf("✅ دامنه اضافه و اعمال شد: %s", domain))
	return true
}

// addIP mirrors addDomain for IP/CIDR entries.
func (b *Bot) addIP(chatID int64, entry string) bool {
	entry = strings.TrimSpace(entry)
	added, err := config.AppendCIDR(b.cidrsFile, entry)
	if err != nil {
		b.reply(chatID, fmt.Sprintf("❌ %v\nدوباره بفرست یا /cancel بزن.", err))
		return false
	}
	if !added {
		b.reply(chatID, fmt.Sprintf("این آی‌پی از قبل توی لیست هست: %s", entry))
		return true
	}
	if err := b.reload(); err != nil {
		b.reply(chatID, fmt.Sprintf("آی‌پی اضافه شد ولی اعمال (reload) شکست خورد: %v", err))
		return true
	}
	b.reply(chatID, fmt.Sprintf("✅ آی‌پی اضافه و اعمال شد: %s", entry))
	return true
}

func (b *Bot) list(chatID int64) {
	domains, err := config.ReadList(b.domainsFile)
	if err != nil {
		b.reply(chatID, fmt.Sprintf("خطا در خواندن دامنه‌ها: %v", err))
		return
	}
	ips, err := config.ReadList(b.cidrsFile)
	if err != nil {
		b.reply(chatID, fmt.Sprintf("خطا در خواندن آی‌پی‌ها: %v", err))
		return
	}
	b.reply(chatID, fmt.Sprintf("دامنه‌ها (%d):\n%s\n\nآی‌پی‌های مجاز (%d):\n%s",
		len(domains), strings.Join(domains, "\n"),
		len(ips), strings.Join(ips, "\n")))
}

type inlineKeyboardButton struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data"`
}

type inlineKeyboardMarkup struct {
	InlineKeyboard [][]inlineKeyboardButton `json:"inline_keyboard"`
}

func (b *Bot) sendMenu(chatID int64) {
	markup := &inlineKeyboardMarkup{InlineKeyboard: [][]inlineKeyboardButton{
		{{Text: "➕ افزودن دامنه", CallbackData: "add_domain"}},
		{{Text: "➕ افزودن آی‌پی", CallbackData: "add_ip"}},
		{{Text: "📋 لیست فعلی", CallbackData: "list"}},
	}}
	b.send(chatID, "چی می‌خوای اضافه کنی؟", markup)
}

func (b *Bot) reply(chatID int64, text string) {
	b.send(chatID, text, nil)
}

func (b *Bot) send(chatID int64, text string, markup *inlineKeyboardMarkup) {
	payload := map[string]any{"chat_id": chatID, "text": text}
	if markup != nil {
		payload["reply_markup"] = markup
	}
	data, _ := json.Marshal(payload)
	resp, err := b.client.Post(b.api("sendMessage"), "application/json", bytes.NewReader(data))
	if err != nil {
		log.Printf("telegram bot: sendMessage: %v", err)
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
}

func (b *Bot) answerCallback(id string) {
	data, _ := json.Marshal(map[string]any{"callback_query_id": id})
	resp, err := b.client.Post(b.api("answerCallbackQuery"), "application/json", bytes.NewReader(data))
	if err != nil {
		log.Printf("telegram bot: answerCallbackQuery: %v", err)
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
}

func (b *Bot) api(method string) string {
	return apiBase + b.token + "/" + method
}
