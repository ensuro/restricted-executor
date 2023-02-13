// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

import "hardhat/console.sol";

contract AccessControlledContract is AccessControl {
  bytes32 public constant ROLE1 = keccak256("ROLE1");
  bytes32 public constant ROLE2 = keccak256("ROLE2");

  event Role1FunctionExecuted(bytes32 param1, uint256 param2);
  event Role2FunctionExecuted(uint8 param1, address param2);

  constructor() {
    _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
  }

  function role1Function(bytes32 param1, uint256 param2) public onlyRole(ROLE1) {
    emit Role1FunctionExecuted(param1, param2);
  }

  function role2Function(uint8 param1, address param2) public onlyRole(ROLE2) {
    emit Role2FunctionExecuted(param1, param2);
  }
}
