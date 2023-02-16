const hre = require("hardhat");
const keccak256 = hre.web3.utils.keccak256;

const { CANCELLER_ROLE } = require("./constants");

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
  const [owner, authorizer, proposer, canceller, ...signers] = await hre.ethers.getSigners();
  const RestrictedExecutor = await hre.ethers.getContractFactory("RestrictedExecutor");
  const restrictedExecutor = await hre.upgrades.deployProxy(RestrictedExecutor, [
    [authorizer.address],
    [proposer.address],
  ]);
  await restrictedExecutor.connect(owner).grantRole(CANCELLER_ROLE, canceller.address);

  const SimpleContract = await hre.ethers.getContractFactory("SimpleContract");
  const callReceiver = await SimpleContract.deploy();

  return {
    owner,
    authorizer,
    proposer,
    canceller,
    signers,
    RestrictedExecutor,
    restrictedExecutor,
    SimpleContract,
    callReceiver,
    receiverEncode: (...args) => callReceiver.interface.encodeFunctionData(...args), // FIXME: is there a cleaner way to do this?
  };
}

async function ownableContractFixture() {
  const [owner, authorizer, proposer, ...signers] = await hre.ethers.getSigners();
  const RestrictedExecutor = await hre.ethers.getContractFactory("RestrictedExecutor");
  const restrictedExecutor = await hre.upgrades.deployProxy(RestrictedExecutor, [
    [authorizer.address],
    [proposer.address],
  ]);

  const OwnableContract = await hre.ethers.getContractFactory("OwnableContract");
  const callReceiver = await OwnableContract.deploy();

  return {
    owner,
    authorizer,
    proposer,
    signers,
    RestrictedExecutor,
    restrictedExecutor,
    AccessControlledContract: OwnableContract,
    callReceiver,
    receiverEncode: (...args) => callReceiver.interface.encodeFunctionData(...args), // FIXME: is there a cleaner way to do this?
  };
}

function createCall(target, data, value, salt) {
  const call = {
    target,
    value: value || 0,
    data,
    salt: salt || hre.ethers.utils.hexZeroPad("0x0", 32),
  };
  call.id = keccak256(
    hre.web3.eth.abi.encodeParameters(
      ["address", "uint256", "bytes", "bytes32"],
      [call.target, call.value, call.data, call.salt]
    )
  );

  return call;
}

function createBatch(targets, payloads, values, salt) {
  values = values || targets.map(() => 0);

  if (!(targets.length === payloads.length && targets.length === values.length))
    throw new Error("All arrays must be the same size");

  const operation = {
    targets,
    values,
    payloads,
    salt: salt || hre.ethers.utils.hexZeroPad("0x0", 32),
  };

  operation.id = keccak256(
    hre.web3.eth.abi.encodeParameters(
      ["address[]", "uint256[]", "bytes[]", "bytes32"],
      [operation.targets, operation.values, operation.payloads, operation.salt]
    )
  );

  return operation;
}

module.exports = {
  accessControlledFixture,
  accessControlMessage,
  createBatch,
  createCall,
  ownableContractFixture,
  simpleContractFixture,
};
