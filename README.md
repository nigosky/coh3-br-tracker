# CoH3 Brasil — Monitor Automático em Nuvem (GitHub Actions + Discord Privado)

Sistema endurecido (*security-hardened* v7) em Python para monitorar o **Ranking Top 20 BR + elenco brasileiro vinculado via SteamID64** de **Company of Heroes 3 (Steam)** em **`1v1`**, **`2v2`** e **`Team Games` (`3v3` + `4v4`)**, gerando tabelas táticas e cards gráficos em PNG automaticamente em um canal privado do Discord.

---

## Arquitetura de Segurança em Primeiro Lugar (`security.py`)

1. **Isolamento Total de Segredos e Redaction Global:**
   - A URL real do Webhook do Discord **nunca** é gravada em `config.json` (`save_config_file` força incondicionalmente um placeholder seguro em qualquer escrita).
   - `SecretRedactingFilter` intercepta globalmente todos os logs e exceções para mascarar qualquer URL ou token de Webhook (`[WEBHOOK_REDACTED]`) antes de chegar ao `stdout` / GitHub Actions.
   - Na nuvem, o segredo vive apenas em **GitHub Encrypted Secrets** (`DISCORD_WEBHOOK_URL`). Localmente, fica isolado em `.env.secret` com permissão `0600` (bloqueado contra symlinks e ignorado pelo `.gitignore`).
   - O workflow executa uma barreira de auditoria *case-insensitive* (`discord.com`, `discordapp.com`, `ptb.discord.com`, `canary.discord.com`) e impede o *staging* de `.env*` / `*.secret` antes de qualquer `git commit`.
2. **Proteção Anti-SSRF, TLS 1.2+ Estrito e Bloqueio de Redirecionamentos:**
   - Todas as conexões HTTPS exigem **TLS 1.2+**, verificação obrigatória de certificado/hostname, porta `443`, ausência de credenciais na URL e *allowlist* estrita de domínios (`coh3-api.reliclink.com`, `discord.com`, `steamcommunity.com` e CDNs oficiais de avatares Steam).
   - `StrictNoRedirectHandler` bloqueia redirecionamentos HTTP `3xx` na API da Relic, no Discord e nas CDNs de avatares; a resolução de perfil XML da Steam limita-se a no máximo 3 saltos validados estritamente em `/id/` ou `/profiles/`.
3. **Proteção contra Bombas de Descompressão (Gzip & Imagem) e Path Traversal:**
   - `read_bounded_http_body` impõe limites rígidos tanto nos bytes trafegados quanto na descompressão incremental Gzip (`zlib.decompressobj` com `max_length`), bloqueando ataques *Gzip Bomb* (CWE-409).
   - Avatares externos passam por verificação de formato (`PNG`/`JPEG`/`WEBP`/`GIF`) e teto de `1024×1024` pixels antes da decodificação (`MAX_IMAGE_PIXELS`).
   - `resolve_safe_db_path` impede *Path Traversal* fora do diretório do projeto e `atomic_write_text` recusa escrita em symlinks.
4. **Anti-Phishing, Anti-Spoofing Visual (BiDi/RLO) e Anti-CSV Injection (CWE-1236):**
   - Todo envio ao Discord fixa `"allowed_mentions": {"parse": []}` (impossível disparar `@everyone`, `@here` ou menções).
   - `strip_unsafe_chars` e `sanitize_discord_text` removem caracteres de controle, *zero-width* e overrides bidirecionais Unicode (`\u202a-\u202e`) usados para falsificação visual de apelidos, além de escapar Markdown/links.
   - `sanitize_csv_cell` neutraliza fórmulas executáveis (`=`, `+`, `-`, `@`, `|`, tabulações e quebras de linha, inclusive precedidas de espaços) nos `.csv` exportados.
5. **Zero Risco de Supply-Chain (`pip`/`npm`) e Container Rootless:**
   - Nenhuma dependência é baixada do PyPI (`pip`): o suporte gráfico (`python3-pil` + fontes) vem exclusivamente de pacotes oficiais Ubuntu/Debian assinados via GPG (`--no-install-recommends`), e `actions/checkout` é fixado por SHA-1 imutável de 40 caracteres com `permissions: {}`.
   - `Dockerfile` e `docker-compose.yml` operam com usuário não-root (`10001:10001`), `read_only: true`, `cap_drop: [ALL]` e `no-new-privileges:true`.

---

## Eficiência e Desempenho (v7)

- **Conexão SQLite Persistente (`thread-local`) + Operações em Lote:** elimina centenas de aberturas de conexão por ciclo, usa `executemany` em `sync_tracked_players`, consulta IDs de partidas em lote (`get_player_match_ids`) e grava atomicamente via `INSERT OR IGNORE`.
- **Compressão Gzip Segura + Paralelismo na API da Relic:** reduz tráfego das leaderboards em ~80%, paraleliza lotes de `getPersonalStat` em `ThreadPoolExecutor` com reserva *lock-free* de *rate-limit* e evita retentativas inúteis em erros definitivos (`400`/`404`).
- **Renderização Gráfica Enxuta:** cache em memória de avatares circulares e brasões vetoriais/PNG das facções (`assets/factions/`), carregamento sob demanda (*lazy*) do catálogo Steam e compressão PNG rápida.

---

## Como ativar na nuvem (GitHub Actions)

1. No repositório do GitHub, acesse **Settings → Secrets and variables → Actions → New repository secret**:
   - **Name:** `DISCORD_WEBHOOK_URL`
   - **Secret:** cole a URL do Webhook do seu canal privado do Discord.
2. Em **Actions → CoH3 Brasil Monitor (Hardened) → Run workflow**, marque **"Enviar/atualizar Painel Fixado PT-BR + 1 Card de exemplo agora?"** se desejar publicar o painel imediatamente.
3. O agendamento roda automaticamente a cada **15 minutos** no horário ativo (11h–02h BRT) e a cada **2 horas** na madrugada, mantendo o consumo dentro da cota gratuita do GitHub Actions.

## Uso via CLI Local ou Docker

```bash
# Configurar Webhook localmente com permissão 0600 em .env.secret
python3 manage.py set-webhook --test

# Executar 1 ciclo completo de sincronização
python3 monitor.py --once

# Consultar jogadores monitorados, histórico local ou ranking
python3 manage.py selected
python3 manage.py history --limit 20
python3 manage.py rankings

# Executar em container isolado (read-only rootfs + non-root)
docker compose up -d --build
```
