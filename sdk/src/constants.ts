/**
 * Official QDay Aevum Testnet constants and tUSD8 token parameters.
 */
export const AEVUM_TESTNET_CONFIG = {
  networkName: "QDay Aevum Testnet",
  chainId: 44005,
  chainIdHex: "0xABE5",
  rpcUrl: "https://rpc-test.qday.info",
  explorerUrl: "https://explorer-test.qday.info",
  nativeCurrency: {
    name: "Test QDAY",
    symbol: "tQDAY",
    decimals: 18,
  },
  stablecoin: {
    symbol: "tUSD8",
    name: "Aevum Test USD8",
    address: "0x456569838f1d43009A91ebA4263147Afd7233483",
    decimals: 6,
  },
} as const;

export type AevumTestnetConfig = typeof AEVUM_TESTNET_CONFIG;

