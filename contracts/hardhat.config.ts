import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import * as dotenv from "dotenv";
import * as path from "path";

dotenv.config({ path: path.resolve(__dirname, "../.env") });
dotenv.config();

const DEFAULT_PLACEHOLDER_KEY =
  "0x0000000000000000000000000000000000000000000000000000000000000001";

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.24",
    settings: {
      evmVersion: "cancun",
      viaIR: true,
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
  networks: {
    hardhat: {
      chainId: 44005,
    },
    aevumTestnet: {
      url: process.env.AEVUM_RPC_URL || "https://rpc-test.qday.info",
      chainId: 44005,
      accounts: [process.env.AEVUM_PRIVATE_KEY || DEFAULT_PLACEHOLDER_KEY],
    },
  },
  etherscan: {
    apiKey: {
      aevumTestnet: "empty",
    },
    customChains: [
      {
        network: "aevumTestnet",
        chainId: 44005,
        urls: {
          apiURL: "https://explorer-test.qday.info/api",
          browserURL: "https://explorer-test.qday.info",
        },
      },
    ],
  },
};

export default config;
