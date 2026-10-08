# SHEIK GSM SERVER BOX

Projeto inicial pronto para teste no Render: Node.js/Express + PostgreSQL.

## Deploy
1. Envie todos os arquivos ao GitHub.
2. No Render crie um Web Service.
3. Build Command: `npm install`
4. Start Command: `npm start`
5. Crie/adicione PostgreSQL e configure `DATABASE_URL`.
6. Configure `ADMIN_EMAIL`, `ADMIN_PASSWORD` e `JWT_SECRET`.
7. Abra `/health` após o deploy.

## Segurança
Use somente para equipamentos e contas autorizados. Não inclua credenciais, segredos ou chaves no GitHub. O projeto não implementa bypass de autenticação ou exploração de dispositivos.

## Telegram
Defina `TELEGRAM_BOT_TOKEN=true`? Não. Use o token real em `TELEGRAM_BOT_TOKEN` e `TELEGRAM_POLLING=true`. O vínculo Telegram/técnico deve ser feito pelo administrador.

## Agente
O endpoint `/api/agent/heartbeat` aceita `X-Agent-Key` e `boxId` para identificar um agente autorizado.
