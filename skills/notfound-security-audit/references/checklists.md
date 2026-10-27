# Manual review checklists

Use the `entry_points` list in the JSON report as the map. Only check what applies to the detected stack.

## Every project
- [ ] Every endpoint that reads or changes private data checks **who** the user is (authentication) and **whether
      this user may touch this object** (authorisation). Look for IDs taken from the URL/body and used directly in
      queries (IDOR).
- [ ] Admin routes/actions are protected server-side, not only hidden in the UI.
- [ ] Passwords hashed with bcrypt/argon2/scrypt; reset tokens random, single-use, expiring.
- [ ] Session cookies: `HttpOnly`, `Secure`, `SameSite`; sessions rotated on login; logout invalidates server-side.
- [ ] CSRF protection on state-changing requests that use cookies.
- [ ] File uploads: type and size checked server-side, stored outside the web root or in object storage, never
      executed, filenames not trusted.
- [ ] Outbound requests built from user input (webhooks, URL previews, image fetchers) restrict hosts — SSRF.
- [ ] Errors do not leak stack traces, queries or environment in production.
- [ ] Secrets only in server-side environment variables; nothing secret behind `NEXT_PUBLIC_`, `VITE_`,
      `REACT_APP_`, `EXPO_PUBLIC_`.
- [ ] Dependencies and runtime on supported, patched versions; lockfile committed.
- [ ] LLM features: user content cannot instruct the model to call privileged tools; model output is escaped
      before rendering; API keys stay on the server.

## Next.js
- [ ] Server Actions and Route Handlers re-check auth inside the function (middleware alone is not enough).
- [ ] No secrets passed to Client Components as props.
- [ ] `dangerouslySetInnerHTML` only with sanitised or JSON-serialised (escaped `<`) content.
- [ ] `next.config` `images.remotePatterns` restricted; `dangerouslyAllowSVG` off unless needed.
- [ ] Security headers set (CSP, HSTS, frame-ancestors); `next` on a patched version.

## PHP / Laravel / WordPress
- [ ] Queries use bindings (`?`, named params, Eloquent); no `$_GET`/`$request` concatenated into SQL.
- [ ] Blade uses `{{ }}`; `{!! !!}` only for trusted HTML.
- [ ] `$fillable`/`$guarded` set; no `$request->all()` into `create()`/`update()` on sensitive models.
- [ ] `APP_DEBUG=false` and a strong `APP_KEY` in production; `.env` not web-accessible.
- [ ] PHP itself patched (`php -v` on the server); `display_errors=Off`, `expose_php=Off`.
- [ ] WordPress: core, plugins and themes updated; unused plugins removed; nonces + capability checks in AJAX
      handlers.

## Node.js / Express
- [ ] `helmet()`; CORS limited to known origins when credentials are used.
- [ ] No `child_process` with user input (use `execFile`/`spawn` with an argument array).
- [ ] Body size limits; JSON schema validation (zod, joi…).
- [ ] Node.js runtime patched.

## Python / Django / Flask / FastAPI
- [ ] ORM or parameterised queries; no f-strings in `execute()`.
- [ ] `DEBUG=False`, real `ALLOWED_HOSTS`, secure cookies in production.
- [ ] No `pickle`/`yaml.load` on untrusted data; `|safe` / `Markup` only on trusted content.

## Supabase / Firebase
- [ ] RLS enabled on every table in `public`, with policies that check `auth.uid()`.
- [ ] Service-role key only in server code; the browser uses the anon/publishable key.
- [ ] Storage buckets: public only when intended; policies on private buckets.
- [ ] Firebase rules require `request.auth` and check ownership; no `if true`.

## Docker / deployment
- [ ] Non-root `USER`; pinned base image; rebuilt with `--pull` after security releases.
- [ ] No secrets in `ENV`/`ARG`; use runtime env or build secrets.
- [ ] Databases not published on public interfaces; no `privileged`, no `docker.sock` mounts.

## CI (GitHub Actions)
- [ ] No `${{ github.event.* }}` user-controlled fields inside `run:`; pass them through `env:`.
- [ ] `pull_request_target` never checks out and runs PR code.
- [ ] Minimal `permissions:`; third-party actions pinned to a commit SHA.
