import * as dotenv from "dotenv";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import hardhatToolboxMochaEthersPlugin from "@nomicfoundation/hardhat-toolbox-mocha-ethers";
import { defineConfig } from "hardhat/config";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.resolve(__dirname, "../.env") });
dotenv.config();

const DEFAULT_PLACEHOLDER_KEY =
  "0x0000000000000000000000000000000000000000000000000000000000000001";

export default defineConfig({
  plugins: [hardhatToolboxMochaEthersPlugin],
  solidity: {
    profiles: {
      default: {
        version: "0.8.24",
        settings: {
          optimizer: {
            enabled: true,
            runs: 200,
          },
          viaIR: true,
        },
      },
      production: {
        version: "0.8.24",
        settings: {
          optimizer: {
            enabled: true,
            runs: 200,
          },
          viaIR: true,
        },
      },
    },
  },
  networks: {
    hardhatMainnet: {
      type: "edr-simulated",
      chainType: "l1",
    },
    aevumTestnet: {
      type: "http",
      chainType: "l1",
      url: process.env.AEVUM_RPC_URL || "https://rpc-test.qday.info",
      chainId: 44005,
      accounts: [process.env.AEVUM_PRIVATE_KEY || DEFAULT_PLACEHOLDER_KEY],
    },
  },
});

