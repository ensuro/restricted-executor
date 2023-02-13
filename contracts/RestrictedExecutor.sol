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
   *
   * @param target the target contract
   * @param value the ether amount to send along with the transaction
   * @param data the encoded payload for the target contract (an encoded function call)
   * @param salt a salt to ensure action id unicity, usually just zero
   * @return hash the action hash / id
   */
  function hashAction(
    address target,
    uint256 value,
    bytes calldata data,
    bytes32 salt
  ) public pure virtual returns (bytes32 hash) {
    return keccak256(abi.encode(target, value, data, salt));
  }

  /**
   *
   * @dev Creates a new action. Check hashAction for parameter details.
   *
   * Requirements:
   *   - onlyRole(PROPOSER_ROLE)
   *
   * Events:
   *   - ActionCreated with the action id and details
   *   - RoleAdminChanged granting AUTHORIZER_ROLE admin on the new action
   */
  function createAction(
    address target,
    uint256 value,
    bytes calldata data,
    bytes32 salt
  ) public virtual onlyRole(PROPOSER_ROLE) {
    bytes32 id = hashAction(target, value, data, salt);
    _actions[id] = true;
    _setRoleAdmin(id, AUTHORIZER_ROLE);
    emit ActionCreated(id, target, value, data, salt);
  }

  /**
   *
   * @dev Executes an action. Check hashAction for parameter details.
   *
   * Requirements:
   *   - Action was created
   *   - msg.sender has been granted permissions on the action
   */
  function execute(
    address target,
    uint256 value,
    bytes calldata data,
    bytes32 salt
  ) public virtual {
    bytes32 id = hashAction(target, value, data, salt);
    require(_actions[id], "RestrictedExecutor: unkwnown action");
    _checkRole(id);

    (bool success, ) = target.call{value: value}(data);
    require(success, "RestrictedExecutor: underlying transaction reverted");
  }
}
