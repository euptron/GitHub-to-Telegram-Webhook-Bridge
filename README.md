# GitHub to Telegram Webhook Bridge

A Cloudflare Worker that forwards GitHub webhook events to a Telegram group thread with formatted messages. Perfect for receiving real-time notifications about repository activities in your Telegram chat.

## Features

- 📨 **Real-time Notifications**: Receive GitHub events instantly in Telegram
- 🔒 **Secure**: Optional HMAC signature verification for GitHub payloads
- 🧩 **Multiple Event Support**: Handles push, pull requests, issues, comments, releases, and more
- 🧵 **Topic Support**: Sends messages to specific topics/threads in Telegram Supergroups
- 📝 **Markdown Formatting**: Clean, formatted messages with links and context

## Supported GitHub Events

✅ Push Events  
✅ Pull Requests (opened, closed, merged, labeled, assigned)  
✅ Issues (opened, closed, labeled, assigned)  
✅ Issue Comments  
✅ Commit Comments  
✅ Releases (published, edited, deleted)  
✅ Create/Delete Events (branches, tags)  
✅ Forks  
✅ Stars  
✅ Watch Events  

## Installation

### Prerequisites

1. Cloudflare account with Workers access
2. Telegram bot token from [@BotFather](https://t.me/BotFather)
3. Telegram Supergroup with message threads enabled
4. GitHub repository with webhook permissions

### Setup Steps

1. **Deploy the Worker**
   - Create a new Cloudflare Worker
   - Copy/paste the provided code
   - Add required environment variables in Worker Settings -> Secrets:
     - `COS_TELEGRAM_BOT_TOKEN`
     - `COS_TELEGRAM_CHAT_ID`
     - `COS_TELEGRAM_MESSAGE_THREAD_ID`
     - `COS_TIMELESS_GITHUB_SECRETS` (recommended)

2. **Configure Telegram**
   - Create a bot via [@BotFather](https://t.me/BotFather)
   - Add bot to your supergroup
   - Get your chat ID (use @getmyid_bot)
   - Create a topic thread in your supergroup and note its ID

3. **Set Up GitHub Webhook**
   - Go to your repo Settings -> Webhooks
   - Payload URL: `https://your-worker.your-subdomain.workers.dev`
   - Content type: `application/json`
   - Secret: [use same value as COS_TIMELESS_GITHUB_SECRETS]
   - Select events you want to receive (see supported events above)

## Configuration

### Environment Variables

| Variable Name                     | Description                                                                 |
|-----------------------------------|-----------------------------------------------------------------------------|
| COS_TELEGRAM_BOT_TOKEN           | Telegram bot token from @BotFather                                          |
| COS_TELEGRAM_CHAT_ID             | Telegram group chat ID (usually negative number, use @getmyid_bot to find)   |
| COS_TELEGRAM_MESSAGE_THREAD_ID   | ID of specific thread/topic in your group                                   |
| COS_TIMELESS_GITHUB_SECRETS      | Secret used to verify GitHub webhook payloads (recommended for security)    |

## Usage

Once configured, the worker will automatically:
1. Verify incoming GitHub webhook signatures
2. Parse event payloads
3. Format messages with relevant event details
4. Post to specified Telegram thread

### Testing Your Setup

1. Send test payload using curl:
```bash
curl -X POST -H "Content-Type: application/json" -H "X-GitHub-Event: push" -d '{"repository":{"full_name":"test/repo"},"sender":{"login":"testuser"}}' https://your-worker.url
```

2. Check your Telegram group for the test notification
3. Inspect worker logs in Cloudflare dashboard for errors

## Security

- 🔑 **HMAC Verification**: Enabled when `COS_TIMELESS_GITHUB_SECRETS` is set
- 🛡️ **Validation**: Checks for valid content-type and required headers
- ⚠️ **Warning**: Running without secret verification is not recommended in production

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Submit a Pull Request

Report issues or feature requests in the GitHub Issues section.

## License

[MIT License](LICENSE) - Feel free to use and modify according to your needs.

---

⭐ If you find this useful, please star the repository! → [https://github.com/euptron/CodeOps-Studio](https://github.com/euptron/CodeOps-Studio)
