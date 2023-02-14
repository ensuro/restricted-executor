// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "hardhat/console.sol";

contract SimpleContract {
  event Function1Executed(bytes32 param1, uint256 param2);
  event Function2Executed(uint8 param1, address param2);

  function function1(bytes32 param1, uint256 param2) public {
    emit Function1Executed(param1, param2);
  }

  function function2(uint8 param1, address param2) public {
    emit Function2Executed(param1, param2);
  }

  function revertingFunction() public pure {
    revert("reverting function reverted");
  }
}
