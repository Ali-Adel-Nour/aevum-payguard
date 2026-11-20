import { ethers, network } from "hardhat";
import * as fs from "fs";
import * as path from "path";

const EXPLORER_BASE = process.env.AEVUM_EXPLORER_URL || "https://explorer-test.qday.info";
const DEFAULT_TUSD8 =
  process.env.AEVUM_TUSD8_ADDRESS || "0x456569838f1d43009A91ebA4263147Afd7233483";
const PROTOCOL_FEE_BPS = 25; // 0.25%

async function main() {
  const [deployer] = await ethers.getSigners();
  const networkInfo = await ethers.provider.getNetwork();
  const chainId = Number(networkInfo.chainId);

  console.log("===============================================================");
  console.log("  Aevum PayGuard — Smart Contract Deployment");
  console.log("===============================================================");
  console.log(`Network:   ${network.name} (Chain ID: ${chainId})`);
  console.log(`Deployer:  ${deployer.address}`);

  const balance = await ethers.provider.getBalance(deployer.address);
  console.log(`Balance:   ${ethers.formatEther(balance)} tQDAY\n`);

  // Resolve tUSD8 token (use official Aevum tUSD8 if deployed on target chain, else MockTUSD8)
  let tusd8Address = DEFAULT_TUSD8;
  let isMockToken = false;

  const tusd8Code = await ethers.provider.getCode(DEFAULT_TUSD8);
  if (network.name === "hardhat" || tusd8Code === "0x") {
    console.log("ℹ️  Official tUSD8 not present on this network; deploying MockTUSD8...");
    const MockTUSD8 = await ethers.getContractFactory("MockTUSD8");
    const mockToken = await MockTUSD8.deploy();
    await mockToken.waitForDeployment();
    tusd8Address = await mockToken.getAddress();
    isMockToken = true;
    console.log(`✅ MockTUSD8 deployed:           ${tusd8Address}`);
  } else {
    console.log(`✅ Using Aevum tUSD8:            ${tusd8Address}`);
  }

  // 1. Deploy ERC-8004 Registries
  const IdentityRegistry = await ethers.getContractFactory("AevumIdentityRegistry");
  const identityRegistry = await IdentityRegistry.deploy();
  await identityRegistry.waitForDeployment();
  const identityAddress = await identityRegistry.getAddress();
  console.log(`✅ AevumIdentityRegistry:        ${identityAddress}`);
  console.log(`   Explorer: ${EXPLORER_BASE}/address/${identityAddress}`);

  const ReputationRegistry = await ethers.getContractFactory("AevumReputationRegistry");
  const reputationRegistry = await ReputationRegistry.deploy(identityAddress);
  await reputationRegistry.waitForDeployment();
  const reputationAddress = await reputationRegistry.getAddress();
  console.log(`✅ AevumReputationRegistry:      ${reputationAddress}`);
  console.log(`   Explorer: ${EXPLORER_BASE}/address/${reputationAddress}`);

  const ValidationRegistry = await ethers.getContractFactory("AevumValidationRegistry");
  const validationRegistry = await ValidationRegistry.deploy();
  await validationRegistry.waitForDeployment();
  const validationAddress = await validationRegistry.getAddress();
  console.log(`✅ AevumValidationRegistry:      ${validationAddress}`);
  console.log(`   Explorer: ${EXPLORER_BASE}/address/${validationAddress}`);

  // 2. Resolve AI Validator address (optional AEVUM_VALIDATOR_PRIVATE_KEY, defaults to deployer)
  const validatorAddress = process.env.AEVUM_VALIDATOR_PRIVATE_KEY
    ? new ethers.Wallet(process.env.AEVUM_VALIDATOR_PRIVATE_KEY).address
    : deployer.address;
  const feeRecipient = deployer.address;

  // 3. Deploy AevumEscrowCourt
  const EscrowCourt = await ethers.getContractFactory("AevumEscrowCourt");
  const escrowCourt = await EscrowCourt.deploy(
    identityAddress,
    reputationAddress,
    validationAddress,
    validatorAddress,
    feeRecipient,
    PROTOCOL_FEE_BPS
  );
  await escrowCourt.waitForDeployment();
  const escrowAddress = await escrowCourt.getAddress();
  console.log(`✅ AevumEscrowCourt:             ${escrowAddress}`);
  console.log(`   Explorer: ${EXPLORER_BASE}/address/${escrowAddress}`);

  await (await reputationRegistry.setAuthorizedCourt(escrowAddress, true)).wait();
  await (await validationRegistry.setAuthorizedRecorder(escrowAddress, true)).wait();
  console.log("✅ Authorized AevumEscrowCourt in ERC-8004 Reputation & Validation registries");

  // 4. Deploy AevumAgentVault
  const AgentVault = await ethers.getContractFactory("AevumAgentVault");
  const agentVault = await AgentVault.deploy(deployer.address, reputationAddress, escrowAddress);
  await agentVault.waitForDeployment();
  const vaultAddress = await agentVault.getAddress();
  console.log(`✅ AevumAgentVault:              ${vaultAddress}`);
  console.log(`   Explorer: ${EXPLORER_BASE}/address/${vaultAddress}`);

  const manifest = {
    network: network.name,
    chainId,
    explorerUrl: EXPLORER_BASE,
    tusd8Address,
    isMockToken,
    validatorAddress,
    feeRecipient,
    protocolFeeBps: PROTOCOL_FEE_BPS,
    contracts: {
      identityRegistry: identityAddress,
      reputationRegistry: reputationAddress,
      validationRegistry: validationAddress,
      escrowCourt: escrowAddress,
      agentVault: vaultAddress,
    },
    deployedAt: new Date().toISOString(),
  };

  const outPath = path.resolve(__dirname, "../../deployments.json");
  fs.writeFileSync(outPath, JSON.stringify(manifest, null, 2));
  console.log(`\n📄 Deployment manifest saved to: ${outPath}`);
}

main().catch((err) => {
  console.error("❌ Deployment failed:", err);
  process.exit(1);
});

