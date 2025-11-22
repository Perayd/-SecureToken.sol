// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/*
  SecureToken.sol
  - ERC20 with:
    * AccessControl for roles (DEFAULT_ADMIN_ROLE, MINTER_ROLE, PAUSER_ROLE)
    * ERC20Permit (EIP-2612) for gasless approvals
    * ERC20Snapshot for safe snapshots (governance/dividend use)
    * Pausable to freeze transfers in emergencies
    * Burnable
    * Supply cap (immutable)
    * Optional transfer limits (per-tx and per-wallet) — disabled by default
  - Use multisig as admin in production. Do NOT renounce ownership unless you understand consequences.
*/

import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Snapshot.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/utils/Context.sol";

contract SecureToken is Context, ERC20Burnable, ERC20Snapshot, ERC20Permit, AccessControl, Pausable {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    // immutable cap (in token smallest unit)
    uint256 public immutable CAP;

    // Optional anti-whale limits (0 = disabled)
    uint256 public maxTxAmount;     // max tokens per transfer (0 == disabled)
    uint256 public maxWalletAmount; // max tokens per wallet (0 == disabled)
    bool public limitsEnabled;

    event LimitsUpdated(uint256 maxTx, uint256 maxWallet, bool enabled);

    constructor(
        string memory name_,
        string memory symbol_,
        uint256 cap_,           // supply cap in smallest unit
        uint256 initialMintTo,  // initial mint amount (in smallest unit)
        address admin           // initial admin (multisig recommended)
    ) ERC20(name_, symbol_) ERC20Permit(name_) {
        require(cap_ > 0, "Cap 0");
        CAP = cap_;

        // Setup roles: admin gets DEFAULT_ADMIN_ROLE, MINTER_ROLE, PAUSER_ROLE
        _setupRole(DEFAULT_ADMIN_ROLE, admin);
        _setupRole(MINTER_ROLE, admin);
        _setupRole(PAUSER_ROLE, admin);

        // initial mint if any (must not exceed cap)
        if (initialMintTo > 0) {
            require(initialMintTo <= cap_, "Initial mint > cap");
            _mint(_msgSender(), initialMintTo);
        }
        // defaults: limits disabled
        limitsEnabled = false;
    }

    // ---- Overrides required by Solidity ----
    function _beforeTokenTransfer(address from, address to, uint256 amount)
        internal
        override(ERC20, ERC20Snapshot)
    {
        super._beforeTokenTransfer(from, to, amount);

        // Enforce paused
        require(!paused(), "Token transfer while paused");

        // If limits enabled, enforce them (skip when minting or burning)
        if (limitsEnabled && from != address(0) && to != address(0)) {
            if (maxTxAmount > 0) {
                require(amount <= maxTxAmount, "Transfer exceeds maxTxAmount");
            }
            if (maxWalletAmount > 0) {
                uint256 toBalanceAfter = balanceOf(to) + amount;
                require(toBalanceAfter <= maxWalletAmount, "Recipient wallet limit");
            }
        }
    }

    // ---- Admin / Role functions ----

    /// @notice Mint tokens to a given address. Only MINTER_ROLE.
    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        require(totalSupply() + amount <= CAP, "Cap exceeded");
        _mint(to, amount);
    }

    /// @notice Take a snapshot (for governance/dividends). Only admin (DEFAULT_ADMIN_ROLE).
    function snapshot() external onlyRole(DEFAULT_ADMIN_ROLE) returns (uint256) {
        return _snapshot();
    }

    /// @notice Pause token transfers in an emergency. Only PAUSER_ROLE.
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Unpause token transfers. Only PAUSER_ROLE.
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /// @notice Update anti-whale limits. Only admin. Set to 0 to disable a value.
    function updateLimits(uint256 _maxTxAmount, uint256 _maxWalletAmount, bool _enabled)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        maxTxAmount = _maxTxAmount;
        maxWalletAmount = _maxWalletAmount;
        limitsEnabled = _enabled;
        emit LimitsUpdated(_maxTxAmount, _maxWalletAmount, _enabled);
    }

    // Convenience: expose burner that only admin can call against an account (rare)
    function adminBurn(address account, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _burn(account, amount);
    }

    // ---- Views / Helpers ----

    // Expose role-check helpers to UI or off-chain scripts
    function isAdmin(address who) external view returns (bool) {
        return hasRole(DEFAULT_ADMIN_ROLE, who);
    }

    function isMinter(address who) external view returns (bool) {
        return hasRole(MINTER_ROLE, who);
    }

    function isPauser(address who) external view returns (bool) {
        return hasRole(PAUSER_ROLE, who);
    }

    // ---- Gap for future upgrades (if using proxy pattern) ----
    // uint256[50] private __gap;
}
