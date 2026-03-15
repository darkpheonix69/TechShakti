import hre from "hardhat";

async function main() {
  const Logger = await hre.ethers.getContractFactory("WIDRSLogger");
  const logger = await Logger.deploy();

  await logger.waitForDeployment();

  console.log("WIDRS Logger deployed at:", await logger.getAddress());
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
