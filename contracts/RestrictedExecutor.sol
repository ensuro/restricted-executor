// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

contract RestrictedExecutor is Initializable, AccessControlUpgradeable, UUPSUpgradeable {
  /**
   * @notice Can authorize actions
   */
  bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");

  bytes32 public constant AUTHORIZER_ROLE = keccak256("AUTHORIZER_ROLE");

  bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

  /**
   * @dev actionId -> bool mapping
   */
  mapping(bytes32 => bool) private _actions;

  event ActionCreated(bytes32 indexed id, address target, uint256 value, bytes data, bytes32 salt);

  event ActionExecuted(bytes32 indexed id);

  function initialize(address[] memory authorizers, address[] memory proposers) public initializer {
    __AccessControl_init();
    __UUPSUpgradeable_init();
    __RestrictedExecutor_init_unchained(authorizers, proposers);
  }

  // solhint-disable-next-line func-name-mixedcase
  function __RestrictedExecutor_init_unchained(
    address[] memory authorizers,
    address[] memory proposers
  ) internal onlyInitializing {
    for (uint256 i = 0; i < authorizers.length; ++i) {
      _setupRole(AUTHORIZER_ROLE, authorizers[i]);
    }

    for (uint256 i = 0; i < proposers.length; ++i) {
      _setupRole(PROPOSER_ROLE, proposers[i]);
    }

    _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
  }

  function _authorizeUpgrade(address) internal override onlyRole(UPGRADER_ROLE) {}

  /**
   * @dev Returns the identifier of an operation containing a single
   * transaction.
   */
  function hashOperation(
    address target,
    uint256 value,
    bytes calldata data,
    bytes32 salt
  ) public pure virtual returns (bytes32 hash) {
    return keccak256(abi.encode(target, value, data, salt));
  }

  function createAction(
    address target,
    uint256 value,
    bytes calldata data,
    bytes32 salt
  ) public virtual onlyRole(PROPOSER_ROLE) {
    bytes32 id = hashOperation(target, value, data, salt);
    _actions[id] = true;
    _setRoleAdmin(id, AUTHORIZER_ROLE);
    emit ActionCreated(id, target, value, data, salt);
  }

  function execute(
    address target,
    uint256 value,
    bytes calldata data,
    bytes32 salt
  ) public virtual {
    bytes32 id = hashOperation(target, value, data, salt);
    // require(_actions[id], "action does not exist");
    _checkRole(id);

    (bool success, ) = target.call{value: value}(data);
    require(success, "RestrictedExecutor: underlying transaction reverted");
  }
}
