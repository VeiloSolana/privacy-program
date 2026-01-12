# Privacy Pool Devnet Deployment Guide

This guide explains how to deploy your privacy pool to Solana devnet with SPL token support.

## Prerequisites

1. **Install Dependencies**
   ```bash
   npm install
   ```

2. **Build the Program**
   ```bash
   anchor build
   ```

3. **Setup Solana Wallet**
   - Ensure you have a Solana wallet at `~/.config/solana/id.json`
   - Or set `ANCHOR_WALLET` environment variable to your wallet path

4. **Get Devnet SOL**
   ```bash
   solana airdrop 2 --url devnet
   ```
   You need at least 1-2 SOL for deployment.

5. **Deploy Program to Devnet**
   ```bash
   anchor deploy --provider.cluster devnet
   ```

## Usage

### Option 1: Create New Token and Initialize Pool

This is the recommended approach for testing. It will:
- Create a new SPL token
- Mint initial supply to your wallet
- Initialize the privacy pool for this token

```bash
npm run deploy:devnet -- \
  --create-token \
  --token-name "My Privacy Token" \
  --token-symbol "MPT" \
  --decimals 6 \
  --initial-supply 1000000 \
  --fee-bps 50
```

**Parameters:**
- `--create-token`: Flag to create a new token
- `--token-name`: Name of the token (e.g., "My Privacy Token")
- `--token-symbol`: Symbol (e.g., "MPT")
- `--decimals`: Number of decimals (default: 6)
- `--initial-supply`: Initial token supply to mint to your wallet (default: 1000000)
- `--fee-bps`: Pool fee in basis points (50 = 0.5%)

### Option 2: Use Existing Token

If you already have a token mint:

```bash
npm run deploy:devnet -- \
  --token <YOUR_TOKEN_MINT_ADDRESS> \
  --fee-bps 50
```

### Option 3: Add Initial Relayers

You can add relayers during deployment:

```bash
npm run deploy:devnet -- \
  --create-token \
  --token-name "Privacy Coin" \
  --token-symbol "PRIV" \
  --initial-supply 1000000 \
  --fee-bps 50 \
  --relayer <RELAYER_PUBKEY_1> \
  --relayer <RELAYER_PUBKEY_2>
```

### Option 4: Custom RPC URL

```bash
npm run deploy:devnet -- \
  --create-token \
  --token-name "My Token" \
  --token-symbol "MTK" \
  --initial-supply 1000000 \
  --fee-bps 50 \
  --rpc-url https://your-custom-rpc.com
```

## Checking Pool Status

After deployment, you can check the pool status:

```bash
npm run check-pool -- --token <TOKEN_MINT_ADDRESS>
```

This will display:
- Pool configuration (admin, fees, TVL, etc.)
- Vault token account balance
- Merkle tree status
- Nullifiers count
- Links to Solana Explorer

**Options:**
- `--token <address>`: (Required) Token mint address
- `--network <network>`: Network name (default: devnet)
- `--rpc-url <url>`: Custom RPC URL

## Example Output

When you run the deployment script, you'll see:

```
🚀 Privacy Pool Devnet Deployment Script
================================================================================

📍 Connection Details
────────────────────────────────────────────────────────────────────────────────
RPC URL:           https://api.devnet.solana.com
Admin Wallet:      <YOUR_WALLET_ADDRESS>
SOL Balance:       1.5 SOL
Program ID:        8aeAAnLc9TZE5K5Pye9sS7MxxvgeUa5uWYP3JpM8sgHM
✅ Program deployed and executable

🪙 Creating new SPL token...
   Name: My Privacy Token
   Symbol: MPT
   Decimals: 6
   Initial Supply: 1000000
✅ Token mint created: <MINT_ADDRESS>
✅ Admin token account created: <TOKEN_ACCOUNT>
✅ Minted 1000000 tokens to admin wallet
   Transaction: <TX_SIGNATURE>

🏦 Setting up vault token account...
✅ Vault token account created
   Address: <VAULT_TOKEN_ACCOUNT>
   Transaction: <TX_SIGNATURE>

📋 Initializing pool...
✅ Pool initialized!
   Transaction: <INIT_TX_SIGNATURE>

================================================================================
🎉 DEPLOYMENT COMPLETE
================================================================================

[... Full deployment report with all addresses and links ...]

💾 Deployment info saved to: deployments/deployment-1704297600000.json
```

## Deployment Information

All deployment information is saved to `deployments/deployment-<timestamp>.json`:

```json
{
  "network": "devnet",
  "timestamp": "2024-01-03T12:00:00.000Z",
  "programId": "8aeAAnLc9TZE5K5Pye9sS7MxxvgeUa5uWYP3JpM8sgHM",
  "tokenMint": "<YOUR_TOKEN_MINT>",
  "tokenDecimals": 6,
  "pdas": {
    "config": "<CONFIG_PDA>",
    "vault": "<VAULT_PDA>",
    "noteTree": "<NOTE_TREE_PDA>",
    "nullifiers": "<NULLIFIERS_PDA>",
    "vaultTokenAccount": "<VAULT_TOKEN_ACCOUNT>"
  },
  "poolConfig": {
    "admin": "<ADMIN_PUBKEY>",
    "feeBps": 50,
    "minWithdrawalFee": "1000000",
    "maxDepositAmount": "18446744073709551615",
    "paused": false
  },
  "transactions": {
    "tokenCreation": "<TOKEN_CREATION_TX>",
    "initialization": "<INIT_TX>",
    "relayers": []
  }
}
```

## Architecture: Multi-Token Support (v4)

The privacy pool now supports multiple tokens through v4 PDA seeds:

- **Config PDA**: `["privacy_config_v4", mint_address]`
- **Vault PDA**: `["privacy_vault_v4", mint_address]`
- **Note Tree PDA**: `["privacy_note_tree_v4", mint_address]`
- **Nullifiers PDA**: `["privacy_nullifiers_v4", mint_address]`
- **Nullifier Markers**: `["nullifier_v4", mint_address, nullifier]`

Each token has its own isolated:
- Pool configuration
- Vault (for holding deposits)
- Merkle tree (for tracking commitments)
- Nullifier set (for preventing double-spends)

This means you can deploy multiple pools for different tokens on the same program!

## Next Steps After Deployment

1. **Verify on Solana Explorer**
   - Click the explorer links in the deployment output
   - Verify all accounts were created correctly

2. **Test Deposits**
   - Use the SDK to create test deposits
   - Verify commitments are added to the Merkle tree

3. **Test Withdrawals**
   - Generate ZK proofs
   - Execute withdrawals through relayers
   - Verify nullifiers are marked as spent

4. **Add More Relayers** (if needed)
   ```bash
   ts-node scripts/add-relayer.ts
   ```

5. **Monitor Pool Activity**
   ```bash
   npm run check-pool -- --token <YOUR_TOKEN_MINT>
   ```

## Troubleshooting

### "Program not deployed"
Run: `anchor deploy --provider.cluster devnet`

### "Insufficient SOL"
Get more devnet SOL: `solana airdrop 2 --url devnet`

### "Token mint not found"
Make sure the token address is correct and exists on devnet

### "Pool already initialized"
The pool for this token is already initialized. Use `check-pool` to see its status.

### "Wallet not found"
Set the `ANCHOR_WALLET` environment variable or create a wallet at `~/.config/solana/id.json`

## Environment Variables

- `ANCHOR_WALLET`: Path to your Solana wallet keypair (default: `~/.config/solana/id.json`)
- `ANCHOR_PROVIDER_URL`: RPC URL (default: `https://api.devnet.solana.com`)

## Security Notes

- The deployment scripts use your local wallet's private key
- Never commit your wallet keypair to version control
- Test thoroughly on devnet before deploying to mainnet
- For mainnet, consider using a hardware wallet or multi-sig
- Review all transaction parameters before signing

## Support

For issues or questions:
- Check the transaction on Solana Explorer
- Review the deployment JSON file
- Verify all prerequisites are met
- Check your SOL and token balances
