# AegisShare

A self-hosted, zero-knowledge paste and file sharing app. Text and attachments are encrypted in the browser with AES-256-GCM before the encrypted payload is stored in SQLite. The decryption key stays in the URL fragment and is never sent to the server.

## Getting Started

Install dependencies and run the LAN-accessible development server:

```bash
npm run dev
# or
yarn dev
# or
pnpm dev
# or
bun dev
```

Open [http://localhost:3080](http://localhost:3080). The server binds to `0.0.0.0` so another device on the same network can use the generated QR code.

The SQLite database is created at `data/aegisshare.db` on first use. Keep the `data` directory private.

## Features

- Client-side AES-256-GCM encryption
- Optional PBKDF2 password protection
- Text, Markdown preview, and attachments up to 10 MB
- Burn-on-read or timed expiration
- Deletion links and LAN-friendly QR codes

## Production

```bash
npm run build
npm run start
```

The main UI is in `src/app/page.tsx`; API routes live under `src/app/api`.

### Vercel deployment

Vercel functions do not provide persistent local disk storage. Production deployments must use a hosted libSQL database.

1. Create a Turso database and token:

```bash
turso db create aegisshare
turso db show aegisshare
turso db tokens create aegisshare
```

2. Push this repository to GitHub and import it at [vercel.com/new](https://vercel.com/new).
3. Keep the default Next.js settings: the root directory is `.`, the build command is `npm run build`, and the output directory is automatic.
4. In Vercel project settings, open **Environment Variables** and add `TURSO_DATABASE_URL` and `TURSO_AUTH_TOKEN` for Production, Preview, and Development as needed.
5. Redeploy. The application creates its tables automatically on the first API request.

For local development without Turso, leave these variables unset and the app uses `data/aegisshare.db`. Never commit `.env.local` or a Turso token.

The client attachment limit is 2 MB to leave room for encryption and base64 overhead within Vercel serverless request limits. Larger encrypted files should use object storage such as Vercel Blob, with only the file reference stored in Turso.

This project uses [`next/font`](https://nextjs.org/docs/app/building-your-application/optimizing/fonts) to automatically optimize and load [Geist](https://vercel.com/font), a new font family for Vercel.

## Learn More

To learn more about Next.js, take a look at the following resources:

- [Next.js Documentation](https://nextjs.org/docs) - learn about Next.js features and API.
- [Learn Next.js](https://nextjs.org/learn) - an interactive Next.js tutorial.

You can check out [the Next.js GitHub repository](https://github.com/vercel/next.js) - your feedback and contributions are welcome!

## Deploy on Vercel

The easiest way to deploy your Next.js app is to use the [Vercel Platform](https://vercel.com/new?utm_medium=default-template&filter=next.js&utm_source=create-next-app&utm_campaign=create-next-app-readme) from the creators of Next.js.

Check out our [Next.js deployment documentation](https://nextjs.org/docs/app/building-your-application/deploying) for more details.
