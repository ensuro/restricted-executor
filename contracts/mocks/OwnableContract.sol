pragma solidity ^0.8.0;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import "hardhat/console.sol";

contract OwnableContract is Ownable {
  event Function1Executed(bytes32 param1, uint256 param2);
  event Function2Executed(uint8 param1, address param2);

  function function1(bytes32 param1, uint256 param2) public onlyOwner {
    emit Function1Executed(param1, param2);
  }

  function function2(uint8 param1, address param2) public onlyOwner {
    emit Function2Executed(param1, param2);
  }
}
