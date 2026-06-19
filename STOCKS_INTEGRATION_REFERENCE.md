# Veilo Stocks Integration — Resource Reference

Research compiled 2026-06-17. All endpoints verified live unless noted.

---

## Overview of integrations needed

| Feature                | External resource         | Auth required                        |
| ---------------------- | ------------------------- | ------------------------------------ |
| xStocks spot trading   | Jupiter Swap API v2       | API key (keyless at 0.5 RPS for dev) |
| Stock price display    | Pyth Hermes REST/SSE      | None                                 |
| Price history / charts | Birdeye OHLCV API         | API key                              |
| Prediction markets     | Jupiter Prediction API v1 | API key (keyless at 0.5 RPS for dev) |

**Single API key** from [developers.jup.ag/portal](https://developers.jup.ag/portal) unlocks all Jupiter APIs (Swap, Tokens, Prediction, etc.).

---

## 1. xStocks (Backed Finance) — Tokenized Stocks on Solana

### What they are

xStocks are ERC-20–style SPL tokens on Solana that track real US equity prices. Issued by Backed Finance (rebranded to xStocks). Each token is backed 1:1 by the underlying share held in custody.

### Mint addresses

All addresses verified live from Jupiter's token API (`api.jup.ag/tokens/v2/search`). All official xStocks have tags: `verified, xstocks, stocks, rwa, token-2022`. All use **decimals: 8**.

> Symbol format is `<TICKER>x` (e.g. `TSLAx`), not `xTSLA`. All are Token-2022 standard (not legacy SPL).

**Screener:** [jup.ag/terminal/screener/xstocks](https://jup.ag/terminal/screener/xstocks)

```ts
export const XSTOCK_TOKENS = [
  // Core US tech / high-demand stocks
  {
    symbol: "TSLAx",
    name: "Tesla xStock",
    mint: "XsDoVfqeBukxuZHWhdvWHBhgEHjGNst4MLodqsJHzoB",
    decimals: 8,
  },
  {
    symbol: "AAPLx",
    name: "Apple xStock",
    mint: "XsbEhLAtcf6HdfpFZ5xEMdqW8nfAvcsP5bdudRLJzJp",
    decimals: 8,
  },
  {
    symbol: "NVDAx",
    name: "NVIDIA xStock",
    mint: "Xsc9qvGR1efVDFGLrVsmkzv3qi45LTBjeUKSPmx9qEh",
    decimals: 8,
  },
  {
    symbol: "MSFTx",
    name: "Microsoft xStock",
    mint: "XspzcW1PRtgf6Wj92HCiZdjzKCyFekVD8P5Ueh3dRMX",
    decimals: 8,
  },
  {
    symbol: "AMZNx",
    name: "Amazon xStock",
    mint: "Xs3eBt7uRfJX8QUs4suhyU8p2M6DoUDrJyWBa8LLZsg",
    decimals: 8,
  },
  {
    symbol: "GOOGLx",
    name: "Alphabet xStock",
    mint: "XsCPL9dNWBMvFtTmwcCA5v3xWPSMEBCszbQdiLLq6aN",
    decimals: 8,
  },
  {
    symbol: "METAx",
    name: "Meta xStock",
    mint: "Xsa62P5mvPszXL1krVUnU5ar38bBSVcWAB6fmPCo5Zu",
    decimals: 8,
  },
  {
    symbol: "NFLXx",
    name: "Netflix xStock",
    mint: "XsEH7wWfJJu2ZT3UCFeVfALnVA6CP5ur7Ee11KmzVpL",
    decimals: 8,
  },
  // Crypto-adjacent (high relevance to Veilo users)
  {
    symbol: "COINx",
    name: "Coinbase xStock",
    mint: "Xs7ZdzSHLU9ftNJsii5fCeJhoRWSC32SQGzGQtePxNu",
    decimals: 8,
  },
  {
    symbol: "MSTRx",
    name: "MicroStrategy xStock",
    mint: "XsP7xzNPvEHS1m6qfanPUGjNmdnmsLKEoNAnHjdxxyZ",
    decimals: 8,
  },
  {
    symbol: "HOODx",
    name: "Robinhood xStock",
    mint: "XsvNBAYkrDRNhA7wPHQfX3ZUXZyZLdnCQDfHZ56bzpg",
    decimals: 8,
  },
  {
    symbol: "PLTRx",
    name: "Palantir xStock",
    mint: "XsoBhf2ufR8fTyNSjqfU71DYGaE6Z3SUGAidpzriAA4",
    decimals: 8,
  },
  // ETFs / indices
  {
    symbol: "SPYx",
    name: "SP500 xStock",
    mint: "XsoCS1TfEyfFhfvj8EtZ528L3CaKBDBRqRapnBbDF2W",
    decimals: 8,
  },
  {
    symbol: "QQQx",
    name: "Nasdaq xStock",
    mint: "Xs8S1uUs1zvS2p7iwtsG3b6fkhpvmwz4GYU3gWAmWHZ",
    decimals: 8,
  },
  {
    symbol: "TQQQx",
    name: "TQQQ xStock",
    mint: "XsjQP3iMAaQ3kQScQKthQpx9ALRbjKAjQtHg6TFomoc",
    decimals: 8,
  },
  {
    symbol: "VTIx",
    name: "Vanguard xStock",
    mint: "XsssYEQjzxBCFgvYFFNuhJFBeHNdLWYeUSP8F45cDr9",
    decimals: 8,
  },
  {
    symbol: "SMHx",
    name: "VanEck Semiconductor ETF xStock",
    mint: "XstuBvLo7soZzj3beCCPonHpR3eUfPNSeQzw35Swons",
    decimals: 8,
  },
  // Commodities
  {
    symbol: "GLDx",
    name: "Gold xStock",
    mint: "Xsv9hRk1z5ystj9MhnA7Lq4vjSsLwzL2nxrwmwtD3re",
    decimals: 8,
  },
  {
    symbol: "SLVx",
    name: "iShares Silver Trust xStock",
    mint: "XsxAd6okt8y1RRK6gNg7iJaqiWNiq5Md5EDf3ZrF2dm",
    decimals: 8,
  },
  // More equities
  {
    symbol: "AMDx",
    name: "AMD xStock",
    mint: "XsXcJ6GZ9kVnjqGsjBnktRcuwMBmvKWh8S93RefZ1rF",
    decimals: 8,
  },
  {
    symbol: "ORCLx",
    name: "Oracle xStock",
    mint: "XsjFwUPiLofddX5cWFHW35GCbXcSu1BCUGfxoQAQjeL",
    decimals: 8,
  },
  {
    symbol: "AVGOx",
    name: "Broadcom xStock",
    mint: "XsgSaSvNSqLTtFuyWPBhK9196Xb9Bbdyjj4fH3cPJGo",
    decimals: 8,
  },
  {
    symbol: "TSMx",
    name: "TSMC xStock",
    mint: "XsafvsGtzFqqHgTnA3aPC83EAMkacU5mcGtcSayhpVV",
    decimals: 8,
  },
  {
    symbol: "JPMx",
    name: "JPMorgan Chase xStock",
    mint: "XsMAqkcKsUewDrzVkait4e5u4y8REgtyS7jWgCpLV2C",
    decimals: 8,
  },
  {
    symbol: "BRK_Bx",
    name: "Berkshire Hathaway xStock",
    mint: "Xs6B6zawENwAbWVi7w92rjazLuAr5Az59qgWKcNb45x",
    decimals: 8,
  },
  {
    symbol: "Vx",
    name: "Visa xStock",
    mint: "XsqgsbXwWogGJsNcVZ3TyVouy2MbTkfCFhCGGGcQZ2p",
    decimals: 8,
  },
  {
    symbol: "MAx",
    name: "Mastercard xStock",
    mint: "XsApJFV9MAktqnAc6jqzsHVujxkGm9xcSUffaBoYLKC",
    decimals: 8,
  },
  {
    symbol: "KOx",
    name: "Coca-Cola xStock",
    mint: "XsaBXg8dU5cPM6ehmVctMkVqoiRG2ZjMo1cyBJ3AykQ",
    decimals: 8,
  },
  {
    symbol: "PGx",
    name: "Procter & Gamble xStock",
    mint: "XsYdjDjNUygZ7yGKfQaB6TxLh2gC6RRjzLtLAGJrhzV",
    decimals: 8,
  },
  {
    symbol: "XOMx",
    name: "Exxon Mobil xStock",
    mint: "XsaHND8sHyfMfsWPj6kSdd5VwvCayZvjYgKmmcNL5qh",
    decimals: 8,
  },
  {
    symbol: "CVXx",
    name: "Chevron xStock",
    mint: "XsNNMt7WTNA2sV3jrb1NNfNgapxRF5i4i6GcnTRRHts",
    decimals: 8,
  },
  {
    symbol: "LLYx",
    name: "Eli Lilly xStock",
    mint: "Xsnuv4omNoHozR6EEW5mXkw8Nrny5rB3jVfLqi6gKMH",
    decimals: 8,
  },
  {
    symbol: "UNHx",
    name: "UnitedHealth xStock",
    mint: "XszvaiXGPwvk2nwb3o9C1CX4K6zH8sez11E6uyup6fe",
    decimals: 8,
  },
  {
    symbol: "PFEx",
    name: "Pfizer xStock",
    mint: "XsAtbqkAP1HJxy7hFDeq7ok6yM43DQ9mQ1Rh861X8rw",
    decimals: 8,
  },
  {
    symbol: "ABTx",
    name: "Abbott xStock",
    mint: "XsHtf5RpxsQ7jeJ9ivNewouZKJHbPxhPoEy6yYvULr7",
    decimals: 8,
  },
  {
    symbol: "AZNx",
    name: "AstraZeneca xStock",
    mint: "Xs3ZFkPYT2BN7qBMqf1j1bfTeTm1rFzEFSsQ1z3wAKU",
    decimals: 8,
  },
  {
    symbol: "MRVLx",
    name: "Marvell xStock",
    mint: "XsuxRGDzbLjnJ72v74b7p9VY6N66uYgTCyfwwRjVCJA",
    decimals: 8,
  },
  {
    symbol: "INTCx",
    name: "Intel xStock",
    mint: "XshPgPdXFRWB8tP1j82rebb2Q9rPgGX37RuqzohmArM",
    decimals: 8,
  },
  {
    symbol: "MUx",
    name: "Micron Technology xStock",
    mint: "XsQLZycSZ7QnBBdBXQaTbQdiUcbRqjNJgyBGAMzhHav",
    decimals: 8,
  },
  {
    symbol: "MCDx",
    name: "McDonald's xStock",
    mint: "XsqE9cRRpzxcGKDXj1BJ7Xmg4GRhZoyY1KpmGSxAWT2",
    decimals: 8,
  },
  {
    symbol: "IBMx",
    name: "IBM xStock",
    mint: "XspwhyYPdWVM8XBHZnpS9hgyag9MKjLRyE3tVfmCbSr",
    decimals: 8,
  },
  {
    symbol: "CSCOx",
    name: "Cisco xStock",
    mint: "Xsr3pdLQyXvDJBFgpR5nexCEZwXvigb8wbPYp4YoNFf",
    decimals: 8,
  },
  {
    symbol: "GMEx",
    name: "Gamestop xStock",
    mint: "Xsf9mBktVB9BSU5kf4nHxPq5hCBJ2j2ui3ecFGxPRGc",
    decimals: 8,
  },
  {
    symbol: "SNDKx",
    name: "Sandisk xStock",
    mint: "Xswbpc8UqU6e1j9QZEWCjBMjyvz4twqD7PCy6j2e7jj",
    decimals: 8,
  },
  {
    symbol: "CRCLx",
    name: "Circle xStock",
    mint: "XsueG8BtpquVJX9LVLLEGuViXUungE6WmK5YZ3p3bd1",
    decimals: 8,
  },
  {
    symbol: "SPCXx",
    name: "SpaceX xStock",
    mint: "Xs3oZwbHvqis4NYcf4YKWmEia2eC84wSiVrcYcTqpH8",
    decimals: 8,
  },
  {
    symbol: "XLEx",
    name: "Energy Select Sector SPDR xStock",
    mint: "Xs54CrhmpVp6uxZXwgSTegrRH2kShh88XFPzgf4BExu",
    decimals: 8,
  },
];
```

**Token-2022 note:** These are Token-2022 (not legacy SPL). The Jupiter swap infrastructure handles this transparently, but if you ever need to fetch token accounts directly use `TOKEN_2022_PROGRAM_ID` (`TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`).

**How to discover new tokens added after this doc:** Query `GET https://api.jup.ag/tokens/v2/search?query=xstock&skip=0&limit=50` and filter for entries where `tags` includes both `"xstocks"` and `"rwa"` and `"verified"`.

### How swaps work

xStocks are standard SPL tokens — Jupiter routes swaps through them identically to USDC or SOL. No special handling required.

**Integration point in Veilo:** Add xStock mints to `SUPPORTED_TOKENS` in [wallet-app/src/lib/swap/config.ts](wallet-app/src/lib/swap/config.ts). No relayer or core-sdk changes needed.

```ts
// Add to getSupportedTokens() in config.ts
{
  symbol: "xTSLA",
  mintAddress: "<verified_mint_address>",
  decimals: 8,
  logoUri: "https://app.xstocks.fi/icons/xTSLA.png", // verify URL
  tags: ["stock"],   // add tags field to SwapToken type for tab filtering
}
```

### Market hours caveat

xStocks trade 24/7 on Solana DEXes but the underlying stock price only updates during NYSE hours (09:30–16:00 ET, Mon–Fri). Outside those hours, the token price floats freely on-chain. Display a "Market closed — price may deviate" banner when outside NYSE hours.

---

## 2. Pyth Network — Price Feeds

### Overview

Pyth publishes equity price feeds via **Hermes**, a REST/SSE service. No authentication needed. Updates every 5 seconds during market hours.

**Base URL:** `https://hermes.pyth.network`

### Key endpoints

#### Fetch latest price for one or more feeds

```
GET /v2/updates/price/latest
  ?ids[]=<feedId>
  &ids[]=<feedId>
  &parsed=true
  &encoding=hex
```

**Response shape:**

```json
{
  "binary": { "encoding": "hex", "data": [...] },
  "parsed": [
    {
      "id": "16dad506d7db8da01c87581c87ca897a012a153557d4d578c3b9c9e1bc0632f1",
      "price": {
        "price": "40473000",
        "conf": "33000",
        "expo": -5,
        "publish_time": 1781640021
      },
      "ema_price": {
        "price": "40558360",
        "conf": "25751",
        "expo": -5,
        "publish_time": 1781640021
      },
      "metadata": {
        "slot": 297189887,
        "proof_available_time": 1781655790,
        "prev_publish_time": 1781640021
      }
    }
  ]
}
```

**Decode price:**

```ts
const humanPrice = Number(price.price) * Math.pow(10, price.expo);
// e.g. 40473000 * 10^-5 = $404.73
```

#### Streaming (SSE)

```
GET /v2/updates/price/stream?ids[]=<feedId>
```

Returns `text/event-stream`. Each `data:` event is the same shape as the latest endpoint. Use for live price tickers. Note: React Native requires `EventSource` polyfill (e.g. `react-native-sse`).

#### Search for a feed ID by symbol

```
GET /v2/price_feeds?asset_type=equity&query=TSLA
```

Returns array of matching feeds. Use the one without `.PRE`, `.POST`, or `.ON` suffix for regular hours.

### Verified equity feed IDs (regular market hours)

All IDs are for `Equity.US.<SYMBOL>/USD` (09:30–16:00 ET schedule, non-deprecated):

Keys match the `symbol` field in `XSTOCK_TOKENS` minus the trailing `x`:

```ts
export const PYTH_EQUITY_FEEDS: Record<string, string> = {
  TSLA: "16dad506d7db8da01c87581c87ca897a012a153557d4d578c3b9c9e1bc0632f1",
  AAPL: "49f6b65cb1de6b10eaf75e7c03ca029c306d0357e91b5311b175084a5ad55688",
  NVDA: "b1073854ed24cbc755dc527418f52b7d271f6cc967bbf8d8129112b18860a593",
  MSFT: "d0ca23c1cc005e004ccf1db5bf76aeb6a49218f43dac3d4b275e92de12ded4d1",
  AMZN: "b5d0e0fa58a1f8b81498ae670ce93c872d14434b72c364885d4fa1b257cbb07a",
  GOOGL: "5a48c03e9b9cb337801073ed9d166817473697efff0d138874e0f6a33d6d5aa6",
  META: "78a3e3b8e676a8f73c439f5d749737034b139bbbe899ba5775216fba596607fe",
  NFLX: "8376cfd7ca8bcdf372ced05307b24dced1f15b1afafdeff715664598f15a3dd2",
  COIN: "fee33f2a978bf32dd6b662b65ba8083c6773b494f8401194ec1870c640860245",
  MSTR: "e1e80251e5f5184f2195008382538e847fafc36f751896889dd3d1b1f6111f09",
  SPY: "19e09bb805456ada3979a7d1cbb4b6d63babc3a0f8e8a9509f68afa5c4c11cd5",
  QQQ: "9695e2b96ea7b3859da9ed25b7a46a920a776e2fdae19a7bcfdf2b219230452d",
  // Lookup remaining tickers via: GET https://hermes.pyth.network/v2/price_feeds?asset_type=equity&query=<TICKER>
  // Use the entry with symbol "Equity.US.<TICKER>/USD" (no .PRE/.POST/.ON suffix, non-deprecated)
};

// Helper: derive ticker from xStock symbol (e.g. "TSLAx" → "TSLA")
export const tickerFromXStock = (symbol: string) => symbol.replace(/x$/, "");
```

### Market hours check

Pyth publishes prices during market hours only. Outside hours `publish_time` will be stale (>15 min old). Detect this:

```ts
const isStale = (publishTime: number) => Date.now() / 1000 - publishTime > 900; // 15 min threshold
```

### Package

No SDK needed — pure REST calls. If you want on-chain verified prices (for any smart contract use), use `@pythnetwork/client`:

```bash
npm install @pythnetwork/hermes-client  # optional, just wraps REST
```

---

## 3. Jupiter Swap API — Stock Token Swaps

**Base URL:** `https://api.jup.ag`
**Auth header:** `x-api-key: <your_key>`
**Keyless rate limit:** 0.5 RPS (sufficient for dev, not production)
**Get a key:** [developers.jup.ag/portal](https://developers.jup.ag/portal)

### Quote

```
GET /swap/v2/quote
  ?inputMint=<mint>
  &outputMint=<mint>
  &amount=<lamports_or_smallest_unit>
  &slippageBps=50
```

This is already implemented in Veilo at [wallet-app/src/lib/swap/providers/](wallet-app/src/lib/swap/providers/). No changes needed — just pass xStock mint addresses as `outputMint`.

### Swap transaction

Already implemented via `executeSwap` / `executePrivateSwap` in [wallet-app/src/lib/swap/privateSwap.ts](wallet-app/src/lib/swap/privateSwap.ts). Works identically for xStock mints.

---

## 4. Jupiter Prediction Market API

**Base URL:** `https://api.jup.ag/prediction/v1`
**Auth header:** `x-api-key: <your_key>`
**Keyless rate limit:** 0.5 RPS
**Existing playground:** [prediction-playground/](prediction-playground/) — all 6 flows already scripted

### All endpoints

#### GET /events

List all prediction events.

```
GET /events?status=live&category=economics&limit=20&offset=0
```

Query params:
| Param | Values | Default |
|-------|--------|---------|
| `status` | `live`, `closed`, `all` | — |
| `category` | `crypto`, `sports`, `politics`, `esports`, `culture`, `economics`, `tech` | — |
| `limit` | number | 20 |
| `offset` | number | 0 |

Response shape (from live data):

```json
{
  "data": [
    {
      "eventId": "POLY-30615",
      "isActive": true,
      "isLive": false,
      "category": "economics",
      "subcategory": "economy",
      "tags": ["fed-rates", "economic-policy"],
      "metadata": {
        "slug": "...",
        "title": "Will the Fed cut rates by September 2026?",
        "isLive": false,
        "series": "polymarket",
        "eventId": "POLY-30615",
        "imageUrl": "https://polymarket-upload.s3.us-east-2.amazonaws.com/...",
        "closeTime": "2026-09-01T00:00:00Z"
      },
      "volumeUsd": "2515396845000000",
      "volume24hr": "95080172000000",
      "closeCondition": "This market will resolve Yes if...",
      "markets": [
        {
          "provider": "polymarket",
          "marketId": "POLY-558936",
          "status": "open",
          "title": "Yes",
          "outcomes": ["Yes", "No"],
          "pricing": {
            "buyYesPriceUsd": 185000,
            "sellYesPriceUsd": 184000,
            "buyNoPriceUsd": 816000,
            "sellNoPriceUsd": 815000,
            "volume": 58032553
          }
        }
      ]
    }
  ],
  "pagination": {
    "start": 0,
    "end": 20,
    "total": 56,
    "hasNext": true
  }
}
```

**Price decoding:** All prices are in micro-USD. Divide by 1,000,000 for USD.

```ts
const priceUsd = pricing.buyYesPriceUsd / 1_000_000; // e.g. 0.185 = 18.5% chance
```

#### GET /events/{eventId}

Get a single event with all markets.

#### GET /markets/{marketId}

Get market details + current pricing.

#### GET /orderbook/{marketId}

Bid/ask depth.

#### POST /orders — Buy

```json
{
  "ownerPubkey": "<user_wallet_pubkey>",
  "marketId": "POLY-558936",
  "isYes": true,
  "isBuy": true,
  "amountUsd": 5000000
}
```

Returns: `{ "transaction": "<base64_encoded_unsigned_tx>" }`
User signs and submits via their wallet.

#### POST /orders — Sell

Same shape with `"isBuy": false`.

#### DELETE /orders

Cancel pending order.

#### GET /positions?ownerPubkey=<pubkey>

```json
[
  {
    "positionPubkey": "...",
    "marketId": "POLY-558936",
    "isYes": true,
    "contracts": 100,
    "costUsd": 18500000,
    "currentValueUsd": 21000000,
    "pnlUsd": 2500000,
    "claimable": false,
    "claimed": false,
    "payoutUsd": 0,
    "status": "open",
    "marketMetadata": { "title": "Yes", "result": null }
  }
]
```

#### POST /positions/{positionPubkey}/claim

Claim winnings after market resolves. Returns unsigned transaction.

#### GET /history?ownerPubkey=<pubkey>

Transaction history with event types.

### Stock-specific events

Currently, the `economics` category includes macro events (Fed rates, GDP etc.) rather than individual stock price events. To offer stock-specific prediction markets you would need to **create your own events** via the Jupiter prediction API (endpoint documented at developers.jup.ag/portal, requires verified account). Alternatively, filter `economics` events for any stock-adjacent events.

### Existing Veilo code

The full flow is already implemented in [prediction-playground/](prediction-playground/):

- `1_events.ts` — list events (maps to `GET /events`)
- `2_markets.ts` — list markets for an event
- `3_buy.ts` — buy contracts
- `4_positions.ts` — list positions
- `5_sell.ts` — sell contracts
- `6_claim.ts` — claim winnings

Port these into React hooks: `usePredictionEvents`, `usePredictionPositions`, `usePredictionOrder`.

---

## 5. Birdeye — Historical Price / OHLCV

Used for price charts on stock token detail screens (xTSLA etc).

**Base URL:** `https://public-api.birdeye.so`
**Auth:** `X-API-KEY: <your_key>` header (get key at [birdeye.so](https://birdeye.so) → BDS Dashboard → Security)
**Auth error response:** HTTP 401

### OHLCV endpoint

```
GET /defi/ohlcv
  ?address=<token_mint>
  &type=<interval>
  &time_from=<unix_ts>
  &time_to=<unix_ts>
```

Interval options: `1m`, `3m`, `5m`, `15m`, `30m`, `1H`, `2H`, `4H`, `6H`, `8H`, `12H`, `1D`, `3D`, `1W`, `1M`
Max records: 1000 per request

Response shape:

```json
{
  "data": {
    "items": [
      {
        "unixTime": 1700000000,
        "open": 234.56,
        "high": 237.89,
        "low": 233.1,
        "close": 236.45,
        "volume": 12345.67
      }
    ]
  },
  "success": true
}
```

### Alternative: skip Birdeye for Q3

For a simpler initial approach, omit charts entirely and show only the live Pyth price + 24h change. Birdeye can be added in a fast-follow once the core flow is working.

### OHLCV v3 (enhanced)

```
GET /defi/v3/ohlcv
  ?address=<token_mint>
  &type=<interval>
  &time_from=<unix_ts>
  &time_to=<unix_ts>
```

Supports shorter intervals (1s, 15s, 30s) and up to 5000 records. Prefer this over v1.

---

## 6. Geo-blocking Requirement

Before any stocks UI ships, US person detection must be live. Standard approach:

### IP-based detection

Use a free IP geolocation API at the relayer layer:

```
GET https://ipapi.co/json/  → { "country_code": "US", ... }
GET https://ip-api.com/json/ → { "country": "United States", ... }
```

Block at the relayer endpoint, not just the frontend, to prevent bypass.

### Wallet-based heuristics (supplementary)

- Reject wallets registered on Coinbase or other KYC'd US exchanges (not reliable alone)
- Show attestation checkbox: "I confirm I am not a US person" before first stock trade

### Where to add in Veilo

Add a `geo` check middleware to the relayer-server before any `/swap` routes that involve xStock mints. Map of stock mints → requires geo check.

---

## 7. API Keys needed

| Service           | Where to get                                                 | Cost                | Required for                 |
| ----------------- | ------------------------------------------------------------ | ------------------- | ---------------------------- |
| Jupiter API key   | [developers.jup.ag/portal](https://developers.jup.ag/portal) | Free tier available | Production swap + prediction |
| Birdeye API key   | [birdeye.so](https://birdeye.so) → BDS Dashboard             | Free tier available | OHLCV charts                 |
| Pyth Hermes       | No key needed                                                | Free                | Price feeds                  |
| xStocks mint list | [app.xstocks.fi](https://app.xstocks.fi)                     | Free                | Token list compilation       |

---

## 8. What to build — in order

### Step 1: Add xStocks to swap (no new APIs)

1. Verify mint addresses at app.xstocks.fi
2. Add `tags: ["stock"]` field to `SwapToken` type in [wallet-app/src/lib/swap/types.ts](wallet-app/src/lib/swap/types.ts)
3. Add xStock entries to `getSupportedTokens()` in [wallet-app/src/lib/swap/config.ts](wallet-app/src/lib/swap/config.ts)
4. Add "Stocks" tab filter to [wallet-app/app/(main)/swap.tsx](<wallet-app/app/(main)/swap.tsx>) that shows only `tags.includes("stock")` tokens
5. Add market hours banner logic using `publish_time` staleness check

### Step 2: Live price display via Pyth

1. Add `usePythPrice(feedId: string)` hook — polls `GET /v2/updates/price/latest` every 5s
2. Map xStock symbol → Pyth feed ID using `PYTH_EQUITY_FEEDS` table above
3. Show price + 24h change % on token selector and token detail screen
4. Show "Market closed" state when price is stale

### Step 3: Price history charts via Birdeye (optional for Q3)

1. Get Birdeye API key
2. Add `useStockOHLCV(mint, interval, from, to)` hook calling `GET /defi/v3/ohlcv`
3. Render with [victory-native](https://commerce.nearform.com/open-source/victory-native/) (already likely in wallet-app) or add `react-native-gifted-charts`

### Step 4: Prediction markets

1. Create `usePredictionEvents(category?, status?)` hook — port of `prediction-playground/1_events.ts`
2. Create `usePredictionPositions(ownerPubkey)` hook — port of `4_positions.ts`
3. Create `usePredictionOrder` hook for buy/sell/claim — ports of `3_buy.ts`, `5_sell.ts`, `6_claim.ts`
4. Wire up existing [wallet-app/app/(main)/predict.tsx](<wallet-app/app/(main)/predict.tsx>) to use these hooks
5. Filter events to `economics` + `tech` categories for stock-adjacent relevance
