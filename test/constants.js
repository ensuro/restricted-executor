const hre = require("hardhat");

const keccak256 = hre.web3.utils.keccak256;

// RestrictedExecutor roles
const PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
const AUTHORIZER_ROLE = keccak256("AUTHORIZER_ROLE");
const CANCELLER_ROLE = keccak256("CANCELLER_ROLE");
const UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

// AccessControlledContract roles
const ROLE1 = keccak256("ROLE1");
const ROLE2 = keccak256("ROLE2");

//
const DEFAULT_ADMIN_ROLE = hre.ethers.utils.hexZeroPad("0x0", 32);

module.exports = { PROPOSER_ROLE, AUTHORIZER_ROLE, CANCELLER_ROLE, UPGRADER_ROLE, ROLE1, ROLE2, DEFAULT_ADMIN_ROLE };
