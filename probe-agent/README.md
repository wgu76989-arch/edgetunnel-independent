# ARM probe agent

This service performs the TLS probe from the ARM machine's own network and
returns the target response plus the measured probe latency.

## Configuration

Copy `.env.example` to `.env` and set `PROBE_TOKEN` to a random value. Keep
the same value in the Cloudflare Worker secret named `PROBE_RELAY_TOKEN`.

The default SNI is `eee21.albb.ccwu.cc`. The agent connects to the candidate
IP while sending this hostname as both TLS SNI and HTTP Host.

## Native Node.js

```bash
npm start
```

The service listens on `127.0.0.1:8788` by default. Expose it through a
Cloudflare Tunnel with the public hostname mapped to:

```text
http://127.0.0.1:8788
```

The tunnel public URL is the value for the Worker variable
`PROBE_RELAY_URL`, including the `/probe` path.

## Docker

```bash
docker build -t edgetunnel-probe-agent .
docker run -d --name edgetunnel-probe-agent --restart unless-stopped \
  --env-file .env -p 127.0.0.1:8788:8788 edgetunnel-probe-agent
```

## API

```text
GET /health
GET /probe?ip=172.64.229.139&port=8443&sni=eee21.albb.ccwu.cc
GET /speed?ip=172.64.229.139&port=8443&sni=eee21.albb.ccwu.cc&bytes=20000000
Authorization: Bearer <PROBE_TOKEN>
```

The probe and speed endpoints only allow public IP addresses and the
configured TLS ports. They reject unauthorized requests and do not resolve
hostnames. `/probe` reports TCP connection latency as `probeLatency`, while
`/speed` downloads a bounded sample through the target Worker and returns
`speedMbps`.
