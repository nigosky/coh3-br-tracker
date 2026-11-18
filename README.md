# CoH3 Brasil — Monitor Automático em Nuvem (GitHub Actions + Discord Privado)

Sistema endurecido (*security-hardened*) em Python puro (zero dependências externas — zero risco de cadeia de suprimentos `pip`/`npm`) para monitorar os **Top 20 jogadores brasileiros** de **Company of Heroes 3 (Steam)** em **`1v1`**, **`2v2`** e **`Team Games` (`3v3` + `4v4`)** e publicar automaticamente em um canal privado do Discord.

---

## Arquitetura de Segurança Aplicada

1. **Isolamento Total de Segredos (Zero texto plano no Git):**
   - A URL do Webhook do Discord **nunca** é salva em `config.json` (há bloqueio ativo em `save_config_file` / `save_config` e barreira de auditoria no GitHub Actions que aborta qualquer commit caso detecte padrões de Webhook).
   - Na nuvem, o Webhook vive exclusivamente no cofre criptografado **GitHub Encrypted Secrets** (`DISCORD_WEBHOOK_URL`), injetado apenas em memória durante a execução.
   - Localmente (opcional), fica isolado em `.env.secret` com permissão restrita `0600` (somente leitura do dono) e bloqueado pelo `.gitignore`.
2. **Proteção Anti-SSRF, TLS 1.2+ Estrito e Bloqueio de Redirecionamentos:**
   - `DiscordWebhookClient` aceita unicamente `https://` nos domínios oficiais do Discord (`discord.com` / `discordapp.com`) validados por expressão regular estrita, bloqueando qualquer redirecionamento HTTP (`3xx`), credenciais em URL e respostas acima de `256 KB`.
   - `RelicAPIClient` aceita unicamente `https://coh3-api.reliclink.com` com verificação obrigatória de certificado TLS 1.2+, bloqueio de redirecionamentos e teto de `5 MB` por resposta.
3. **Anti-Phishing e Bloqueio de Menções Indevidas no Discord:**
   - Todo payload enviado ao Discord define `"allowed_mentions": {"parse": []}` (impossível um apelido da Steam disparar `@everyone`, `@here` ou marcar membros/cargos).
   - `sanitize_discord_text` escapa caracteres de controle e Markdown (`[link](url)`, `<...>`, `@`, `*`, `` ` ``) em apelidos e mapas vindos da API pública.
4. **Anti-CSV Formula Injection (CWE-1236):**
   - `sanitize_csv_cell` neutraliza prefixos executáveis (`=`, `+`, `-`, `@`, `\t`, `\r`) nos arquivos `.csv` exportados para Excel / Google Sheets.
5. **GitHub Actions Endurecido (Supply-Chain & Privilégio Mínimo):**
   - Repositório pode ser **100% Privado** e **100% Gratuito** (agendado a cada `25 min` = `~1.728 min/mês`, abaixo da franquia gratuita de `2.000 min/mês` do GitHub Free).
   - `permissions: {}` global (privilégio mínimo), `actions/checkout` fixado por **SHA-1 imutável de 40 caracteres** (imune a sequestro de tags) e variáveis passadas apenas via `env:` (imune a *Script Injection*).

---

## Como ativar na nuvem (GitHub Actions — Sem deixar nada rodando no PC)

1. Suba este repositório como **Privado** na sua conta do GitHub.
2. No repositório do GitHub, acesse **Settings → Secrets and variables → Actions → New repository secret**:
   - **Name:** `DISCORD_WEBHOOK_URL`
   - **Secret:** cole a URL do Webhook do seu canal privado do Discord.
3. Vá na aba **Actions** → **CoH3 Brasil Monitor (Hardened)** → clique em **Run workflow**, marque **"Enviar Lista Resumo inicial + 1 Card de teste agora?"** e clique no botão verde **Run workflow**.
4. No seu canal do Discord, clique nos `⋯` da mensagem **"📌 Lista de Partidas Gravadas"** → **Fixar mensagem**. Pronto: o GitHub cuidará de tudo sozinho na nuvem!
