const hre = require("hardhat");
const keccak256 = hre.web3.utils.keccak256;

const accessControlMessage = (address, role) =>
  `AccessControl: account ${address.toLowerCase()} is missing role ${role}`;

async function accessControlledFixture() {
  const [owner, authorizer, proposer, ...signers] = await hre.ethers.getSigners();
  const RestrictedExecutor = await hre.ethers.getContractFactory("RestrictedExecutor");
  const restrictedExecutor = await hre.upgrades.deployProxy(RestrictedExecutor, [
    [authorizer.address],
    [proposer.address],
  ]);

  const AccessControlledContract = await hre.ethers.getContractFactory("AccessControlledContract");
  const callReceiver = await AccessControlledContract.deploy();

  return {
    owner,
    authorizer,
    proposer,
    signers,
    RestrictedExecutor,
    restrictedExecutor,
    AccessControlledContract,
    callReceiver,
    receiverEncode: (...args) => callReceiver.interface.encodeFunctionData(...args), // FIXME: is there a cleaner way to do this?
  };
}

async function simpleContractFixture() {
  const [owner, authorizer, proposer, ...signers] = await hre.ethers.getSigners();
  const RestrictedExecutor = await hre.ethers.getContractFactory("RestrictedExecutor");
  const restrictedExecutor = await hre.upgrades.deployProxy(RestrictedExecutor, [
    [authorizer.address],
    [proposer.address],
  ]);

  const SimpleContract = await hre.ethers.getContractFactory("SimpleContract");
  const callReceiver = await SimpleContract.deploy();

  return {
    owner,
    authorizer,
    proposer,
    signers,
    RestrictedExecutor,
    restrictedExecutor,
    SimpleContract,
    callReceiver,
    receiverEncode: (...args) => callReceiver.interface.encodeFunctionData(...args), // FIXME: is there a cleaner way to do this?
  };
}

function createAction(target, data, value, salt) {
  const action = {
    target,
    value: value || 0,
    data,
    salt: salt || hre.ethers.utils.hexZeroPad("0x0", 32),
  };
  action.id = keccak256(
    hre.web3.eth.abi.encodeParameters(
      ["address", "uint256", "bytes", "bytes32"],
      [action.target, action.value, action.data, action.salt]
    )
  );

  return action;
}

function createActionBatch(targets, payloads, values, salt) {
  values = values || targets.map(() => 0);

  if (!(targets.length === payloads.length && targets.length === values.length))
    throw new Error("All arrays must be the same size");

  const action = {
    targets,
    values,
    payloads,
    salt: salt || hre.ethers.utils.hexZeroPad("0x0", 32),
  };

  action.id = keccak256(
    hre.web3.eth.abi.encodeParameters(
      ["address[]", "uint256[]", "bytes[]", "bytes32"],
      [action.targets, action.values, action.payloads, action.salt]
    )
  );

  return action;
}

module.exports = {
  accessControlledFixture,
  createAction,
  createActionBatch,
  simpleContractFixture,
  accessControlMessage,
};
