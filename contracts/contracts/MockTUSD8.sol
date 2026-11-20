// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @title MockTUSD8
 * @notice Local 6-decimal test stablecoin matching QDay Aevum Testnet's tUSD8
 *         (0x456569838f1d43009A91ebA4263147Afd7233483), with optional transfer-fee
 *         simulation to test Fee-On-Transfer (FOT) accounting resilience.
 */
contract MockTUSD8 is ERC20 {
    address public owner;
    address public pendingOwner;
    uint16 public transferFeeBps;
    address public feeSink;

    error OnlyOwner();
    error OnlyPendingOwner();
    error InvalidAddress();
    error FeeTooHigh();
    error InvalidFeeSink();

    event TransferFeeUpdated(uint16 feeBps, address feeSink);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor() ERC20("Aevum Test USD8", "tUSD8") {
        owner = msg.sender;
        _mint(msg.sender, 1_000_000 * 10 ** 6);
    }

    function decimals() public pure override returns (uint8) {
        return 6;
    }

    /**
     * @notice Faucet helper for local tests and testnet demos.
     */
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    /**
     * @notice Configures an optional fee-on-transfer rate (max 10% = 1000 bps) for testing.
     */
    function setTransferFee(uint16 _feeBps, address _feeSink) external {
        if (msg.sender != owner) revert OnlyOwner();
        if (_feeBps > 1000) revert FeeTooHigh();
        if (_feeBps > 0 && _feeSink == address(0)) revert InvalidFeeSink();
        transferFeeBps = _feeBps;
        feeSink = _feeSink;
        emit TransferFeeUpdated(_feeBps, _feeSink);
    }

    function transferOwnership(address newOwner) external {
        if (msg.sender != owner) revert OnlyOwner();
        if (newOwner == address(0)) revert InvalidAddress();
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert OnlyPendingOwner();
        address previousOwner = owner;
        owner = pendingOwner;
        pendingOwner = address(0);
        emit OwnershipTransferred(previousOwner, owner);
    }

    function _update(address from, address to, uint256 value) internal override {
        if (
            transferFeeBps > 0 &&
            from != address(0) &&
            to != address(0) &&
            from != feeSink &&
            to != feeSink
        ) {
            uint256 fee = (value * transferFeeBps) / 10_000;
            uint256 netAmount = value - fee;
            if (fee > 0) {
                super._update(from, feeSink, fee);
            }
            super._update(from, to, netAmount);
        } else {
            super._update(from, to, value);
        }
    }
}

