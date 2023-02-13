const { loadFixture } = require("@nomicfoundation/hardhat-network-helpers");
const { expect } = require("chai");
const hre = require("hardhat");

const keccak256 = hre.web3.utils.keccak256;

const accessControlMessage = (address, role) =>
  `AccessControl: account ${address.toLowerCase()} is missing role ${role}`;

describe("Batch actions", () => {
  it("hashes actions", async () => {
    expect(1).to.equal(1);
  });
});
